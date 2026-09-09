"""
flask_aegis.rules.open_redirect
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-REDIRECT-001: open redirect detection.

Targets common bypass techniques for redirect-target allowlists rather
than "any absolute URL" -- a field like `next=/dashboard` is completely
normal and would false-positive constantly if flagged; the actual risk
is a value that *looks* relative or trusted but resolves to an
attacker-controlled host once a browser parses it.

Opt-in per field (like CSV injection), since only fields that are
actually used as a redirect target are meaningful to check -- see
false_positive_notes.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

# Each pattern targets a specific, well-known open-redirect bypass
# technique rather than "contains http://", which would just flag every
# legitimate absolute URL.
_PROTOCOL_RELATIVE = re.compile(r"^\s*/{2,}")                      # //evil.com
_BACKSLASH_TRICK = re.compile(r"^\s*/\\|^\s*\\/|^\s*\\{2,}")          # /\evil.com, \\evil.com
_CREDENTIALS_HOST = re.compile(r"^\s*https?://[^/@]+@", re.IGNORECASE)  # http://trusted@evil.com
_ENCODED_SLASHES = re.compile(r"%2f%2f", re.IGNORECASE)                # %2f%2f encoded //
_CONTROL_CHAR_PREFIX = re.compile(r"^[\x00-\x1f\s]*https?://", re.IGNORECASE)  # tab/newline before scheme


class OpenRedirectRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-REDIRECT-001",
        category="open_redirect",
        severity="medium",
        description=(
            "Detects common open-redirect bypass techniques in fields "
            "used as a redirect target: protocol-relative URLs (//evil.com), "
            "backslash tricks (/\\evil.com), embedded credentials before "
            "the real host (http://trusted@evil.com), URL-encoded double "
            "slashes, and control characters preceding a scheme to evade "
            "naive string-prefix checks."
        ),
        mitigation=(
            "Block the request, or better: validate the redirect target "
            "against an explicit allowlist of paths/hosts before "
            "redirecting, rather than trying to blocklist every bypass. "
            "`werkzeug.urls.url_parse` plus a same-host check is the "
            "durable fix; this rule is a safety net for the fields you "
            "haven't gotten to yet."
        ),
        false_positive_notes=(
            "This rule is opt-in per field (default off) precisely "
            "because most fields are never used as a redirect target, "
            "and even among those that are, a plain absolute URL to a "
            "*trusted* external partner is a completely normal thing to "
            "redirect to (e.g. an OAuth callback). Enable it with "
            "`aegis.field(route, field_name, open_redirect=True)` only "
            "on fields your view actually passes to `redirect()`."
        ),
        limitations=(
            "This is a bypass-technique detector, not a same-origin "
            "validator -- it will not catch a syntactically ordinary "
            "absolute URL to an untrusted host (e.g. plain "
            "'https://evil.com'), because that's indistinguishable from "
            "a legitimate external redirect without an allowlist. Pair "
            "this rule with an actual allowlist check in your view."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "open_redirect", default=False):
                continue
            for pattern, detail in (
                (_PROTOCOL_RELATIVE, "protocol-relative URL"),
                (_BACKSLASH_TRICK, "backslash bypass"),
                (_CREDENTIALS_HOST, "embedded credentials before real host"),
                (_ENCODED_SLASHES, "URL-encoded double slash"),
                (_CONTROL_CHAR_PREFIX, "control character before scheme"),
            ):
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential open redirect ({detail}) in field '{field_name}'",
                        severity=self.meta.severity,
                        score=20,
                        meta={"field": field_name, "detail": detail},
                    )
        return None
