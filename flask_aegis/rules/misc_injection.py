"""
flask_aegis.rules.misc_injection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-HEADER-001 (HTTP header / log injection via CRLF) and
AEGIS-CSV-001 (CSV/formula injection). Grouped together because both are
"injection via a specific output sink" rather than a query-language
injection, and both are cheap, string-level checks.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_CRLF_PATTERN = re.compile(r"(%0d%0a|%0D%0A|\r\n|\r|\n)", re.IGNORECASE)
_HEADER_INJECTION_KEYWORDS = re.compile(
    r"(set-cookie|location:|content-length:|transfer-encoding:)", re.IGNORECASE
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t=", "\t+")


class HeaderInjectionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-HEADER-001",
        category="header_injection",
        severity="high",
        description=(
            "Detects CRLF sequences (raw or URL-encoded) in request "
            "values destined for response headers, redirect targets, or "
            "log lines -- the primitive behind HTTP response splitting, "
            "log forging, and header/cookie injection."
        ),
        mitigation=(
            "Block the request. Never interpolate a raw request value "
            "into a header, a `Location` redirect target, or a log "
            "format string -- use `werkzeug`'s header-setting APIs "
            "(which reject embedded CRLF) and structured logging "
            "(e.g. pass values as log fields, not into the message "
            "string)."
        ),
        false_positive_notes=(
            "Multi-line textarea input (e.g. an address or comment "
            "field) legitimately contains newlines. Only apply this rule "
            "to fields that flow into headers/redirects/log lines, not "
            "general free-text fields -- use "
            "`aegis.field(route, field_name, header_injection=False)` to "
            "exempt the latter."
        ),
        limitations=(
            "Detects the injection primitive (embedded CRLF), not "
            "whether the application actually uses the value unsafely "
            "downstream."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "header_injection", default=True):
                continue
            if _CRLF_PATTERN.search(value) and _HEADER_INJECTION_KEYWORDS.search(value):
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.BLOCK,
                    message=f"Potential header/log injection payload in field '{field_name}'",
                    severity=self.meta.severity,
                    score=25,
                    meta={"field": field_name},
                )
        return None


class CSVInjectionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-CSV-001",
        category="csv_injection",
        severity="medium",
        description=(
            "Detects CSV/formula injection: field values beginning with "
            "'=', '+', '-', or '@' (optionally after a leading tab), "
            "which spreadsheet applications (Excel, Google Sheets, "
            "LibreOffice) interpret as formulas when the field is later "
            "exported to CSV/XLSX and opened."
        ),
        mitigation=(
            "Sanitize by default (prefix the value with a single quote "
            "or apostrophe on export) rather than blocking outright, "
            "since these are often legitimate values (e.g. a phone "
            "number stored as '+1-555-...' or a negative accounting "
            "figure). Set `xss_action='sanitize'`-style handling per "
            "field if you want SANITIZE instead of BLOCK."
        ),
        false_positive_notes=(
            "Extremely common false-positive surface: phone numbers, "
            "negative numbers, and email signatures starting with '-- ' "
            "all match. Recommended default is to enable this only on "
            "fields that are actually exported to spreadsheet formats, "
            "via `aegis.field(route, field_name, csv_injection=True)` "
            "opt-in rather than blanket enablement."
        ),
        limitations=(
            "Only applicable to data that will later be opened in "
            "spreadsheet software; irrelevant for data that stays in a "
            "database or is only ever rendered as HTML/JSON."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            # Opt-in, not opt-out -- see false_positive_notes above.
            if not ctx.field_option(field_name, "csv_injection", default=False):
                continue
            stripped = value.lstrip()
            if stripped.startswith(_FORMULA_PREFIXES):
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.SANITIZE,
                    message=f"Potential CSV/formula injection payload in field '{field_name}'",
                    severity=self.meta.severity,
                    score=10,
                    meta={"field": field_name},
                )
        return None
