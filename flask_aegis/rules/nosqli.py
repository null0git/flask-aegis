"""
flask_aegis.rules.nosqli
~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-NOSQLI-001: NoSQL injection heuristic detection, targeting the
MongoDB-style query-operator injection pattern (the most common form in
practice, since JSON request bodies map directly onto MongoDB's own
query syntax) and generic JS-evaluation operators used by several
document databases.

This is defense-in-depth, same posture as the SQL injection rule: the
actually-correct defense is never building a query document directly
from unvalidated user input -- validate that a field is a scalar of the
expected type before using it in a filter, rather than passing a
client-supplied dict straight into `.find()`.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_OPERATOR_PATTERN = re.compile(
    r"\$(ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|type|expr|jsonSchema|"
    r"mod|all|elemMatch|size|not|nor|or|and)\b",
    re.IGNORECASE,
)
_JS_EVAL_PATTERN = re.compile(
    r"(this\.|function\s*\(|sleep\s*\(|Object\.keys|return\s+true)", re.IGNORECASE
)
_TRUE_CONDITION_PATTERN = re.compile(r"['\"]?\$where['\"]?\s*:\s*['\"]?1\s*==\s*1")


class NoSQLInjectionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-NOSQLI-001",
        category="nosqli",
        severity="critical",
        description=(
            "Detects NoSQL injection patterns, primarily MongoDB query "
            "operator injection ($ne, $gt, $where, $regex, ...) submitted "
            "as a string value where a scalar was expected, plus "
            "JavaScript-evaluation gadgets ($where clauses invoking "
            "arbitrary JS)."
        ),
        mitigation=(
            "Block the request. Independently, validate that fields used "
            "in a query filter are the scalar type you expect (str/int/"
            "bool) before passing them to the driver -- reject dicts "
            "entirely for fields that should never be one, and never "
            "enable a database's server-side JS evaluation ($where, "
            "mapReduce with untrusted code) on user-influenced input."
        ),
        false_positive_notes=(
            "A field that legitimately discusses MongoDB query syntax "
            "(documentation, a support ticket) will trigger this. Exempt "
            "with `aegis.field(route, field_name, nosqli=False)` for "
            "known free-text technical fields."
        ),
        limitations=(
            "This rule inspects flattened string values (see "
            "RequestContext) -- it catches the common case of an "
            "operator smuggled into a field that should have been a "
            "plain string, but a client sending a genuine nested JSON "
            "object (`{\"username\": {\"$ne\": null}}`) bypasses "
            "string-based detection entirely unless your view also "
            "rejects non-scalar values for that field, which this rule "
            "does not do on your behalf."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "nosqli", default=True):
                continue
            if _TRUE_CONDITION_PATTERN.search(value):
                return self._finding(field_name, "$where tautology")
            if _OPERATOR_PATTERN.search(value):
                return self._finding(field_name, "MongoDB query operator")
            if _JS_EVAL_PATTERN.search(value) and "$" in value:
                return self._finding(field_name, "JS-evaluation gadget")
        return None

    def _finding(self, field_name: str, detail: str) -> Finding:
        return Finding(
            rule_id=self.meta.rule_id,
            decision=Decision.BLOCK,
            message=f"Potential NoSQL injection ({detail}) in field '{field_name}'",
            severity=self.meta.severity,
            score=30,
            meta={"field": field_name, "detail": detail},
        )
