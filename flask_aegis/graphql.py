"""
flask_aegis.graphql
~~~~~~~~~~~~~~~~~~~~~

GraphQL-specific abuse protection: query depth limits, complexity
(field-count) limits, alias-count limits, batch-size limits, and
introspection blocking.

GraphQL's single-endpoint, client-specified-query model sidesteps most
of the URL/parameter-shaped defenses elsewhere in Flask-Aegis -- the
"attack surface" for a GraphQL API is the query document itself, so
protection here operates on the raw query string using a small,
dependency-free tokenizer rather than a full GraphQL parser (adding a
GraphQL parsing library is a reasonable choice for a production GraphQL
service, but this module intentionally has zero new dependencies so it
works out of the box).

Example
-------
>>> from flask_aegis.graphql import GraphQLGuard
>>> guard = GraphQLGuard(max_depth=10, max_complexity=200, allow_introspection=False)
>>> @app.post("/graphql")
... @guard.protect()
... def graphql_endpoint():
...     ...
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from .exceptions import AegisError

_INTROSPECTION_FIELDS = {"__schema", "__type", "__typename"}
# Field-with-optional-alias, using a lookahead for the opening brace/paren
# so this pattern never *consumes* that character itself -- letting the
# separate brace-counting pass see every '{' and '}' independently is
# what makes depth tracking correct (an earlier version let this pattern
# swallow the brace, which silently zeroed out every depth measurement).
_FIELD_NAME_PATTERN = re.compile(r"(?:(\w+)\s*:\s*)?(\w+)(?=\s*[{(]|[\s,}]|$)")
_GRAPHQL_KEYWORDS = {"query", "mutation", "subscription", "fragment", "on", "true", "false", "null"}


class GraphQLBlocked(AegisError):
    """Raised when a GraphQL query fails a configured limit.
    ``reason`` is one of: 'depth_exceeded', 'complexity_exceeded',
    'alias_limit_exceeded', 'introspection_disabled',
    'batch_size_exceeded', 'parse_error'."""

    def __init__(self, reason: str, message: str, **details):
        super().__init__(message)
        self.reason = reason
        self.details = details


@dataclass
class QueryAnalysis:
    depth: int
    field_count: int
    alias_count: int
    uses_introspection: bool
    operation_count: int


def analyze_query(query: str) -> QueryAnalysis:
    """Tokenize a GraphQL query/mutation document just enough to compute
    the metrics Flask-Aegis's limits are checked against. This is
    intentionally not a full GraphQL parser -- it tracks brace nesting
    depth and counts field-like tokens, which is sufficient for depth/
    complexity/alias-count limiting without needing the query to be
    100% syntactically valid GraphQL (a malformed query that still
    trips a limit should still be rejected for exceeding it, not waved
    through because it failed to fully parse).
    """
    operation_count = query.count("query ") + query.count("mutation ") + query.count("subscription ")
    if operation_count == 0 and query.strip():
        operation_count = 1  # shorthand query with no explicit "query" keyword

    # Strip string literals and comments so braces/field-shaped text
    # inside them don't skew the count.
    cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', query)
    cleaned = re.sub(r"#.*", "", cleaned)

    # Pass 1: brace depth, independent of field extraction so a field
    # pattern can never "consume" the brace that should count toward
    # depth (see _FIELD_NAME_PATTERN's lookahead for why that matters).
    depth = 0
    max_depth = 0
    for ch in cleaned:
        if ch == "{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch == "}":
            depth = max(depth - 1, 0)

    # Pass 2: field names (with optional alias), skipping GraphQL
    # keywords so "query", "mutation", "on", etc. don't inflate the
    # field count.
    field_count = 0
    alias_count = 0
    uses_introspection = False
    for match in _FIELD_NAME_PATTERN.finditer(cleaned):
        alias, name = match.group(1), match.group(2)
        if not name or name.lower() in _GRAPHQL_KEYWORDS:
            continue
        field_count += 1
        if alias:
            alias_count += 1
        if name in _INTROSPECTION_FIELDS:
            uses_introspection = True

    return QueryAnalysis(
        depth=max_depth,
        field_count=field_count,
        alias_count=alias_count,
        uses_introspection=uses_introspection,
        operation_count=max(operation_count, 1),
    )


@dataclass
class GraphQLGuard:
    """Enforces depth/complexity/alias/introspection limits on GraphQL
    query documents.

    ``max_complexity`` is measured as total field-selection count
    (a simple, transparent proxy for query cost -- not a replacement
    for per-field cost weighting via a real GraphQL execution library
    if your schema has fields with wildly different actual costs). This
    heuristic counter also counts a named operation's name itself
    (`query GetUser { ... }` counts "GetUser" as a field-like token)
    since distinguishing it from a real field name would require actual
    GraphQL grammar awareness -- this makes the count slightly
    conservative (errs toward stricter, never looser) rather than
    exact."""

    max_depth: int = 10
    max_complexity: int = 200
    max_aliases: int = 15
    """Caps alias-based amplification: requesting the same expensive
    field under many different aliases in one query to multiply its
    cost past what field-count alone would suggest."""
    allow_introspection: bool = True
    max_batch_size: int = 1
    """Some GraphQL clients allow submitting a JSON array of queries in
    one request ('batching') -- cap how many are accepted per request."""

    def analyze(self, query: str) -> QueryAnalysis:
        return analyze_query(query)

    def check(self, query: str) -> Optional[GraphQLBlocked]:
        """Returns a :class:`GraphQLBlocked` describing the first
        violated limit, or ``None`` if the query passes every check."""
        analysis = self.analyze(query)

        if analysis.depth > self.max_depth:
            return GraphQLBlocked(
                "depth_exceeded",
                f"Query depth {analysis.depth} exceeds the limit of {self.max_depth}",
                depth=analysis.depth, limit=self.max_depth,
            )
        if analysis.field_count > self.max_complexity:
            return GraphQLBlocked(
                "complexity_exceeded",
                f"Query field count {analysis.field_count} exceeds the "
                f"complexity limit of {self.max_complexity}",
                field_count=analysis.field_count, limit=self.max_complexity,
            )
        if analysis.alias_count > self.max_aliases:
            return GraphQLBlocked(
                "alias_limit_exceeded",
                f"Query uses {analysis.alias_count} aliases, exceeding "
                f"the limit of {self.max_aliases} (possible alias-based "
                f"amplification attack)",
                alias_count=analysis.alias_count, limit=self.max_aliases,
            )
        if analysis.uses_introspection and not self.allow_introspection:
            return GraphQLBlocked(
                "introspection_disabled",
                "Introspection queries (__schema/__type) are disabled on this endpoint",
            )
        return None

    def check_batch(self, queries: list) -> Optional[GraphQLBlocked]:
        """Checks a batch of queries: the batch-size limit itself, plus
        every individual query in the batch against the normal limits."""
        if len(queries) > self.max_batch_size:
            return GraphQLBlocked(
                "batch_size_exceeded",
                f"Batch of {len(queries)} queries exceeds the limit of {self.max_batch_size}",
                batch_size=len(queries), limit=self.max_batch_size,
            )
        for query in queries:
            blocked = self.check(query)
            if blocked is not None:
                return blocked
        return None

    def protect(self) -> Callable:
        """Decorator: checks the current request's GraphQL query (from
        a JSON body's ``query`` field, or a JSON array for batched
        requests) against this guard's limits before the view runs.
        Raises :class:`GraphQLBlocked` on the first violated limit.

        >>> @app.post("/graphql")
        ... @guard.protect()
        ... def graphql_endpoint():
        ...     ...
        """
        def decorator(view_func: Callable) -> Callable:
            import functools

            from flask import request

            @functools.wraps(view_func)
            def wrapped(*args, **kwargs):
                body = request.get_json(silent=True)
                if isinstance(body, list):
                    queries = [item.get("query", "") for item in body if isinstance(item, dict)]
                    blocked = self.check_batch(queries)
                elif isinstance(body, dict):
                    blocked = self.check(body.get("query", ""))
                else:
                    blocked = GraphQLBlocked("parse_error", "Request body is not a valid GraphQL request")

                if blocked is not None:
                    raise blocked
                return view_func(*args, **kwargs)

            return wrapped

        return decorator
