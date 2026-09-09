"""
flask_aegis.rules.xss
~~~~~~~~~~~~~~~~~~~~~~

AEGIS-XSS-001: heuristic reflected/stored XSS payload detection.

This rule is a *signal*, not a sanitizer. Flask-Aegis's position (see the
README's "Attack Coverage" section) is that output-encoding at render
time is the actually-correct defense against XSS; this rule exists to
flag and optionally block obviously malicious input before it is ever
stored, and to feed the risk engine.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_PATTERNS = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*['\"]", re.IGNORECASE),  # onerror=, onload=, ...
    re.compile(r"<\s*iframe\b", re.IGNORECASE),
    re.compile(r"<\s*svg\b[^>]*on", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
    re.compile(r"</?\s*(img|body|input)\b[^>]*on\w+\s*=", re.IGNORECASE),
]


class XSSRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-XSS-001",
        category="xss",
        severity="high",
        description=(
            "Detects common cross-site scripting payload patterns "
            "(script tags, event-handler attributes, javascript: URIs, "
            "data: URIs carrying HTML) in request parameters, form fields, "
            "and JSON bodies."
        ),
        mitigation=(
            "Flask-Aegis blocks/sanitizes the offending field per policy. "
            "Independently, always output-encode with Jinja's autoescaping "
            "(on by default) or your frontend framework's escaping, and set "
            "a restrictive Content-Security-Policy via aegis.headers()."
        ),
        false_positive_notes=(
            "Fields intentionally accepting HTML (e.g. a rich-text 'bio' "
            "field) will trigger this rule constantly. Use "
            "`aegis.field(route, field_name, html=True)` to exempt fields "
            "that need HTML, and pair with a dedicated HTML sanitizer "
            "(e.g. bleach) rather than disabling detection outright."
        ),
        limitations=(
            "Regex-based detection cannot catch every obfuscation "
            "technique (e.g. deeply nested encoding, mutation XSS). "
            "Treat this as defense-in-depth, not a substitute for "
            "output encoding and a strict CSP."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if ctx.field_option(field_name, "html", default=False):
                continue
            for pattern in _PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.SANITIZE if ctx.field_option(
                            field_name, "xss_action", default=None
                        ) == "sanitize" else Decision.BLOCK,
                        message=f"Potential XSS payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=20,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None
