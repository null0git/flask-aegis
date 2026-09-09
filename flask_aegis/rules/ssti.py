"""
flask_aegis.rules.ssti
~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-SSTI-001: server-side template injection heuristic detection.

Covers the common template-engine delimiter families (Jinja2/Twig,
ERB/Freemarker, Smarty) since payloads are frequently engine-agnostic in
early probing (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`).
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_PATTERNS = [
    re.compile(r"\{\{.*?(config|self|request|__class__|__mro__|__subclasses__|__globals__|__builtins__|lipsum|cycler).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{\s*[\d\s\*\+\-/]{2,}\s*\}\}"),               # {{7*7}}
    re.compile(r"\$\{\s*[\d\s\*\+\-/]{2,}\s*\}"),                  # ${7*7}
    re.compile(r"<%=.*?%>"),                                        # ERB
    re.compile(r"#\{\s*[\d\s\*\+\-/]{2,}\s*\}"),                     # Ruby interpolation probing
    re.compile(r"\{\%\s*(for|if|include|import|macro)\b", re.IGNORECASE),  # Jinja/Twig statement probing
]


class SSTIRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-SSTI-001",
        category="ssti",
        severity="critical",
        description=(
            "Detects server-side template injection probing across the "
            "common delimiter families: Jinja2/Twig ({{ }}, {% %}), "
            "ERB (<%= %>), and generic ${...}/#{...} interpolation, "
            "including attribute-chain payloads targeting Python's "
            "object model (__class__, __mro__, __globals__)."
        ),
        mitigation=(
            "Block the request. The durable fix is to never render "
            "user-controlled strings through `render_template_string` or "
            "an f-string passed to a template engine — always render a "
            "named template file with the user value passed as *data*, "
            "never as template source."
        ),
        false_positive_notes=(
            "Fields that legitimately contain curly braces (JSON snippets, "
            "CSS/LESS samples, math notation) will trigger this rule. "
            "Exempt such fields explicitly with "
            "`aegis.field(route, field_name, ssti=False)`."
        ),
        limitations=(
            "Pattern-based; cannot catch payloads that avoid delimiter "
            "characters entirely (e.g. via a custom filter chain) or "
            "second-order SSTI where the payload is rendered later from "
            "storage rather than in the current request."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "ssti", default=True):
                continue
            for pattern in _PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential SSTI payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=30,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None
