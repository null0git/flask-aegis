"""
flask_aegis.rules.el_injection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-EL-001: Expression Language injection detection.

Targets Java/Spring EL and OGNL injection patterns -- the JVM-world
counterpart to the SSTI rule's Jinja/ERB coverage. Included because a
Flask application is frequently deployed as an API gateway, BFF, or
integration layer in front of (or alongside) Java-based services
(Spring Boot, Struts) in a polyglot stack; a payload that passes through
a Flask-fronted endpoint untouched and reaches a vulnerable Java
component downstream is exactly the kind of gap a perimeter-only WAF
tuned to a single language misses.

As with the other injection rules, defense-in-depth: the durable fix is
never evaluating an expression language against unvalidated input,
whichever service ultimately does the evaluating.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_PATTERNS = [
    # Spring EL / OGNL gadget chains targeting Java's reflection and
    # runtime-exec surface -- the shape used in real Spring4Shell/OGNL
    # injection proofs-of-concept.
    re.compile(r"\$\{.*?(T\s*\(|getRuntime|exec\s*\(|ProcessBuilder).*?\}", re.IGNORECASE),
    re.compile(r"#\{.*?(T\s*\(|getRuntime|exec\s*\(|ProcessBuilder).*?\}", re.IGNORECASE),
    re.compile(r"@[\w.]+@[\w.]+\s*\(", re.IGNORECASE),  # OGNL static method call: @java.lang.Runtime@...
    re.compile(r"ognl\.OgnlContext", re.IGNORECASE),
    re.compile(r"\.getClass\s*\(\s*\)\s*\.forName\s*\(", re.IGNORECASE),
    re.compile(r"class\.module\.classLoader", re.IGNORECASE),  # Spring4Shell-style class-loader access
]


class ELInjectionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-EL-001",
        category="el_injection",
        severity="critical",
        description=(
            "Detects Expression Language injection targeting Java/"
            "Spring EL and OGNL: reflective Runtime/ProcessBuilder "
            "access via T(...) type expressions, OGNL static-method "
            "call syntax (@class@method(...)), and class-loader access "
            "gadgets (the shape used in Spring4Shell-style exploits)."
        ),
        mitigation=(
            "Block the request. Whichever service ultimately evaluates "
            "an expression language, never evaluate one against "
            "unvalidated input -- disable EL evaluation on user-facing "
            "fields entirely where possible, or use a restricted "
            "evaluation context that blocks reflective/class-loader "
            "access."
        ),
        false_positive_notes=(
            "Fields legitimately discussing Java/Spring configuration "
            "syntax (documentation, config-file content, a support "
            "ticket) can trigger this. Exempt with "
            "`aegis.field(route, field_name, el_injection=False)` for "
            "known free-text technical fields."
        ),
        limitations=(
            "Pattern-based; covers the common, publicly-documented "
            "gadget shapes rather than the full space of possible EL "
            "expressions. A Flask application with no Java/Spring "
            "component anywhere in its stack gets no benefit from this "
            "rule and can safely disable it."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "el_injection", default=True):
                continue
            for pattern in _PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential Expression Language injection payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=30,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None
