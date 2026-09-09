"""
flask_aegis.rules.xml_bomb
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-XMLBOMB-001: XML entity expansion bomb ("billion laughs") detection.

Distinct from AEGIS-XXE-001 (which targets external entity references
for file disclosure/SSRF): this rule targets *internal* entity
definitions that reference each other, causing exponential expansion
when the parser resolves them -- a few kilobytes of XML expanding to
gigabytes in memory, a denial-of-service that doesn't require any
external network access at all.

As with XXE, the durable defense is parser configuration: disable DTD
processing entirely, or cap entity expansion depth/count
(`defusedxml`'s default protections cover this).
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_ENTITY_DEF = re.compile(r"<!ENTITY\s+(\w+)\s+[\"']([^\"']*)[\"']", re.IGNORECASE)
# A reference like &name; that isn't one of the five predefined XML
# entities (lt, gt, amp, apos, quot).
_PREDEFINED = {"lt", "gt", "amp", "apos", "quot"}
_ENTITY_REF = re.compile(r"&(\w+);")

# Above this many internal entity definitions in one document, treat it
# as suspicious regardless of whether we can prove exponential blowup --
# legitimate documents essentially never define this many.
_SUSPICIOUS_ENTITY_COUNT = 8


class XMLBombRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-XMLBOMB-001",
        category="xml_bomb",
        severity="high",
        description=(
            "Detects XML entity expansion bombs ('billion laughs'): "
            "internal ENTITY definitions that reference other defined "
            "entities, which a parser without expansion limits resolves "
            "recursively -- a small document expanding to an "
            "enormous one in memory. Flags both explicit "
            "entity-references-entity chains and a simple volume "
            "heuristic (many ENTITY definitions in one document)."
        ),
        mitigation=(
            "Block the request. Independently, configure your XML "
            "parser to cap entity expansion (defusedxml's defaults "
            "handle this) or disable DTD processing entirely -- most "
            "applications have no legitimate need for internal entity "
            "definitions in submitted XML at all."
        ),
        false_positive_notes=(
            "Legitimate XML using a handful of internal entities for "
            "genuine reuse (a document template with a few named "
            "boilerplate strings) can trigger the volume heuristic if "
            "it defines more than a handful. Raise the threshold or "
            "disable this rule for routes with a known, legitimate use "
            "of internal entities."
        ),
        limitations=(
            "Only applies to bodies whose Content-Type indicates XML "
            "(see RequestContext.raw_body), same as AEGIS-XXE-001. "
            "Does not itself compute the actual expansion factor -- it "
            "flags the structural shape (entities referencing "
            "entities, or an unusually high definition count), not a "
            "proven memory-exhaustion outcome."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.raw_body)

    def check(self, ctx) -> Optional[Finding]:
        body = ctx.raw_body
        definitions = _ENTITY_DEF.findall(body)
        if not definitions:
            return None

        defined_names = {name for name, _ in definitions}

        for name, value in definitions:
            refs = set(_ENTITY_REF.findall(value)) - _PREDEFINED
            if refs & defined_names:
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.BLOCK,
                    message="Potential XML entity expansion bomb: entity definitions reference each other",
                    severity=self.meta.severity,
                    score=30,
                    meta={"entity_count": len(definitions)},
                )

        if len(definitions) > _SUSPICIOUS_ENTITY_COUNT:
            return Finding(
                rule_id=self.meta.rule_id,
                decision=Decision.BLOCK,
                message=f"Unusually high internal ENTITY definition count ({len(definitions)})",
                severity=self.meta.severity,
                score=20,
                meta={"entity_count": len(definitions)},
            )

        return None
