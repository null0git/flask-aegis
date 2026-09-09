"""
flask_aegis.rules.xxe
~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-XXE-001: XML external entity (XXE) injection detection.

Inspects the raw request body (see RequestContext.raw_body, populated
only when the Content-Type indicates XML) for DOCTYPE/ENTITY
declarations -- the primitive behind XXE, whether used for local file
disclosure, SSRF via an external entity URL, or a billion-laughs style
denial of service.

As with the other injection rules, this is defense-in-depth. The
actually-correct defense is disabling DTD processing and external entity
resolution in your XML parser entirely (e.g. `defusedxml`, or
`lxml.etree.XMLParser(resolve_entities=False, no_network=True)`) -- most
applications have no legitimate use for DOCTYPE declarations in
user-submitted XML at all.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_DOCTYPE_PATTERN = re.compile(r"<!DOCTYPE\b", re.IGNORECASE)
_ENTITY_PATTERN = re.compile(r"<!ENTITY\b", re.IGNORECASE)
_SYSTEM_PATTERN = re.compile(r"\bSYSTEM\s+['\"]", re.IGNORECASE)
_PUBLIC_PATTERN = re.compile(r"\bPUBLIC\s+['\"]", re.IGNORECASE)
_PARAMETER_ENTITY_PATTERN = re.compile(r"%\w+;")


class XXERule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-XXE-001",
        category="xxe",
        severity="critical",
        description=(
            "Detects XML external entity (XXE) injection primitives in "
            "XML request bodies: DOCTYPE declarations, ENTITY "
            "definitions, and SYSTEM/PUBLIC external references "
            "(file://, http://) including parameter-entity based "
            "out-of-band exfiltration techniques."
        ),
        mitigation=(
            "Block the request. Independently -- and regardless of this "
            "rule -- configure your XML parser to disable DTD processing "
            "and external entity resolution entirely (e.g. `defusedxml`, "
            "or construct `lxml.etree.XMLParser(resolve_entities=False, "
            "no_network=True, dtd_validation=False)`). Most applications "
            "have no legitimate need for DOCTYPE in submitted XML at all."
        ),
        false_positive_notes=(
            "Legitimate XML documents that declare a DTD for validation "
            "purposes (uncommon in API bodies, more common in "
            "document-upload workflows) will trigger this. If your "
            "application has a genuine, narrow need for DTDs, disable "
            "this rule on that specific route and rely on parser-level "
            "hardening instead."
        ),
        limitations=(
            "Only applies to bodies whose Content-Type indicates XML "
            "(see RequestContext.raw_body) -- an XML payload submitted "
            "with a misleading Content-Type (e.g. text/plain) bypasses "
            "this rule; the parser-level hardening above is the defense "
            "that doesn't depend on the client's stated content type."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.raw_body)

    def check(self, ctx) -> Optional[Finding]:
        body = ctx.raw_body
        if not _DOCTYPE_PATTERN.search(body):
            return None

        detail = "DOCTYPE declaration"
        if _ENTITY_PATTERN.search(body):
            detail = "ENTITY definition"
        if _SYSTEM_PATTERN.search(body) or _PUBLIC_PATTERN.search(body):
            detail = "external SYSTEM/PUBLIC entity reference"
        if _PARAMETER_ENTITY_PATTERN.search(body):
            detail = "parameter entity (possible out-of-band exfiltration)"

        return Finding(
            rule_id=self.meta.rule_id,
            decision=Decision.BLOCK,
            message=f"Potential XXE payload in request body ({detail})",
            severity=self.meta.severity,
            score=30,
            meta={"detail": detail},
        )
