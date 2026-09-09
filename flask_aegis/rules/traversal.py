"""
flask_aegis.rules.traversal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-TRAVERSAL-001: path traversal detection, including URL-encoded
and double-encoded variants.

Also exposes `safe_join_root`, a small helper implementing the property-
tested invariant described in the README: a normalized path must never
resolve outside its configured root.
"""
from __future__ import annotations

import os
import re
import urllib.parse
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_RAW_PATTERN = re.compile(r"\.\./|\.\.\\")


def _fully_decode(value: str, max_rounds: int = 3) -> str:
    """Repeatedly URL-decode a value to catch double/triple-encoded
    traversal sequences like %252e%252e%252f."""
    current = value
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def safe_join_root(root: str, *paths: str) -> Optional[str]:
    """Join ``paths`` onto ``root`` and return the resulting absolute path
    only if it is still contained within ``root``; otherwise return None.

    This is the primitive property-tested in ``tests/property/test_traversal.py``
    under the invariant: *a normalized path must never escape its configured
    root*.
    """
    root_abs = os.path.abspath(root)
    candidate = os.path.abspath(os.path.join(root_abs, *paths))
    if os.path.commonpath([root_abs, candidate]) != root_abs:
        return None
    return candidate


class TraversalRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-TRAVERSAL-001",
        category="traversal",
        severity="high",
        description=(
            "Detects path traversal sequences ('../', '..\\\\') in request "
            "parameters and path segments, including URL-encoded and "
            "double-encoded forms."
        ),
        mitigation=(
            "Block the request. For file-serving endpoints, additionally "
            "use `flask_aegis.rules.traversal.safe_join_root` (or "
            "Werkzeug's `safe_join`) rather than trusting normalization "
            "alone."
        ),
        false_positive_notes=(
            "Rare in practice; legitimate paths almost never contain "
            "literal '../' sequences once through routing."
        ),
        limitations=(
            "Pattern-based detection on the request only; does not "
            "protect against traversal introduced by application code "
            "after the request (e.g. building a path from a database "
            "value)."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values) or bool(ctx.path_segments)

    def check(self, ctx) -> Optional[Finding]:
        candidates = dict(ctx.text_values)
        for i, seg in enumerate(ctx.path_segments):
            candidates[f"__path_segment_{i}"] = seg

        for field_name, value in candidates.items():
            decoded = _fully_decode(value)
            if _RAW_PATTERN.search(value) or _RAW_PATTERN.search(decoded):
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.BLOCK,
                    message=f"Path traversal sequence detected in '{field_name}'",
                    severity=self.meta.severity,
                    score=30,
                    meta={"field": field_name},
                )
        return None
