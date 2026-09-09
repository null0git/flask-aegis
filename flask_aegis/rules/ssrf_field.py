"""
flask_aegis.rules.ssrf_field
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-SSRF-001: SSRF-target detection in request fields.

This is the automatic-detection complement to
`flask_aegis.ssrf.SSRFGuard`, which is a validator your code calls
explicitly at the point it makes an outbound request. This rule instead
flags a field *at request-validation time* if its value looks like a
URL pointing at an internal/reserved address -- useful when you want a
blanket safety net on a field (e.g. "webhook_url") without remembering
to call the guard in every code path that eventually reads it.

The two are complementary, not redundant: this rule catches the input
shape early; SSRFGuard is what actually protects the outbound request
at the moment it's made (including against DNS changing between the two
checks -- see SSRFGuard's docstring on DNS rebinding). Use both.

Opt-in per field (like open_redirect and CSV injection), since most
fields are never used to construct an outbound request.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional
from urllib.parse import urlparse

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_URL_LIKE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", re.IGNORECASE)
_DANGEROUS_SCHEMES = {"file", "gopher", "dict", "ftp", "sftp", "ldap", "tftp"}
# The literal metadata IP is worth naming explicitly even though it also
# falls under is_link_local -- makes the finding's message more useful.
_METADATA_IP = "169.254.169.254"


class SSRFFieldRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-SSRF-001",
        category="ssrf_field",
        severity="critical",
        description=(
            "Flags a field whose value looks like a URL pointing at a "
            "loopback, link-local (including the cloud metadata "
            "address 169.254.169.254), or private address, or using a "
            "non-HTTP(S) scheme (file://, gopher://, dict://, ...) "
            "commonly used in SSRF exploitation."
        ),
        mitigation=(
            "Block the request. Independently, validate any URL your "
            "code actually fetches with `flask_aegis.ssrf.SSRFGuard."
            "validate_url()` immediately before the outbound request -- "
            "this rule protects the field at submission time, "
            "SSRFGuard protects the fetch itself, including against DNS "
            "changing between the two checks."
        ),
        false_positive_notes=(
            "This rule is opt-in per field, like open_redirect and CSV "
            "injection, since only fields actually used to construct an "
            "outbound request are meaningful to check. Enable with "
            "`aegis.field(route, field_name, ssrf_field=True)`. Even "
            "then, a deployment with a legitimate need to reach internal "
            "services (an admin tool hitting an internal API) will need "
            "to disable this for that specific field and rely on "
            "SSRFGuard's `allow_private=True` / `allowed_hosts` instead."
        ),
        limitations=(
            "DNS resolution happens at check time, so a hostname whose "
            "DNS record changes between this check and your code's "
            "actual outbound request (DNS rebinding) is not caught here "
            "-- that's exactly why SSRFGuard exists as a separate, "
            "fetch-time check. A hostname that fails to resolve at all "
            "is not flagged by this rule (that failure will surface "
            "naturally when your code tries to fetch it)."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "ssrf_field", default=False):
                continue
            if not _URL_LIKE.match(value.strip()):
                continue

            detail = self._evaluate(value.strip())
            if detail:
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.BLOCK,
                    message=f"Potential SSRF target ({detail}) in field '{field_name}'",
                    severity=self.meta.severity,
                    score=30,
                    meta={"field": field_name, "detail": detail},
                )
        return None

    @staticmethod
    def _evaluate(url: str) -> Optional[str]:
        parsed = urlparse(url)

        if parsed.scheme.lower() in _DANGEROUS_SCHEMES:
            return f"disallowed scheme '{parsed.scheme}'"

        hostname = parsed.hostname
        if not hostname:
            return None

        if hostname == _METADATA_IP:
            return "cloud metadata address"

        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            try:
                infos = socket.getaddrinfo(hostname, None)
            except (socket.gaierror, UnicodeError):
                return None  # can't resolve -- not this rule's job to flag
            for info in infos:
                addr = info[4][0]
                detail = SSRFFieldRule._classify(ipaddress.ip_address(addr))
                if detail:
                    return detail
            return None

        return SSRFFieldRule._classify(ip)

    @staticmethod
    def _classify(ip) -> Optional[str]:
        if ip.is_loopback:
            return f"loopback address ({ip})"
        if ip.is_link_local:
            return f"link-local address ({ip})"
        if ip.is_private:
            return f"private address ({ip})"
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return f"reserved address ({ip})"
        return None
