"""
flask_aegis.rules.sqli
~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-SQLI-001: heuristic SQL injection payload detection.

As with XSS, this is defense-in-depth. The actually-correct defense
against SQL injection is parameterized queries / an ORM — Flask-Aegis
cannot see how your data layer uses a value, so it can only flag input
that *looks* like an injection attempt.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_PATTERNS = [
    re.compile(r"(\bunion\b\s+\bselect\b)", re.IGNORECASE),
    re.compile(r"(\bor\b|\band\b)\s+['\"]?\d\s*=\s*\d", re.IGNORECASE),
    re.compile(r"(--|#|/\*)\s*$"),  # trailing SQL comment
    re.compile(r"\bsleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"\bbenchmark\s*\(", re.IGNORECASE),
    re.compile(r";\s*(drop|delete|update|insert)\b", re.IGNORECASE),
    re.compile(r"'\s*or\s*'1'\s*=\s*'1", re.IGNORECASE),
    re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
]


class SQLiRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-SQLI-001",
        category="sqli",
        severity="critical",
        description=(
            "Detects common SQL injection patterns: UNION-based, "
            "boolean-based, time-based (SLEEP/BENCHMARK), stacked "
            "queries, and comment-based statement termination."
        ),
        mitigation=(
            "Block the request per policy. This does not replace "
            "parameterized queries — treat any endpoint building SQL by "
            "string concatenation as a defect independent of this rule."
        ),
        false_positive_notes=(
            "Free-text fields discussing SQL syntax (documentation, "
            "code-review comments, a bio mentioning 'SELECT * FROM') can "
            "trigger this rule. Exempt specific fields with "
            "`aegis.field(route, field_name, sqli=False)` where free-form "
            "technical text is expected."
        ),
        limitations=(
            "Cannot detect second-order injection (payload stored now, "
            "used unsafely later) or injection via non-HTTP inputs "
            "(scheduled jobs, message queues)."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "sqli", default=True):
                continue
            for pattern in _PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential SQL injection payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=30,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None
