"""
flask_aegis.rules.homograph
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-HOMOGRAPH-001: homograph / mixed-script spoofing detection.

Flags a value that mixes Latin characters with visually-confusable
characters from another script (Cyrillic, Greek) in a way that
suggests spoofing rather than genuine multilingual content -- the
technique behind lookalike domains ("apple.com" with a Cyrillic 'a'),
impersonation usernames, and phishing display names that visually
match a trusted brand.

Opt-in per field, aimed specifically at identity-like fields (domain,
username, display name) where script-mixing is a red flag rather than
normal usage.
"""
from __future__ import annotations

import unicodedata
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

# A small, well-known set of Cyrillic and Greek characters that are
# visually identical or near-identical to common Latin letters --
# the actual payload of most homograph attacks in practice, rather than
# every possible confusable across all of Unicode.
_CONFUSABLES = {
    "\u0430", "\u0435", "\u043e", "\u0440", "\u0441", "\u0445", "\u0443",
    "\u0456", "\u0458", "\u0455", "\u04bb", "\u0501", "\u051b", "\u0461",
    "\u0391", "\u03b1", "\u03bf", "\u03c1", "\u03b5", "\u03b9", "\u03ba", "\u03bd",
}


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    if name.startswith("LATIN"):
        return "LATIN"
    if name.startswith("CYRILLIC"):
        return "CYRILLIC"
    if name.startswith("GREEK"):
        return "GREEK"
    return "OTHER"


class HomographRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-HOMOGRAPH-001",
        category="homograph",
        severity="medium",
        description=(
            "Detects mixed-script spoofing: a value containing both "
            "Latin letters and visually-confusable Cyrillic/Greek "
            "look-alikes (e.g. Cyrillic 'a' in place of Latin 'a') -- "
            "the technique behind lookalike domains, impersonation "
            "usernames, and brand-spoofing display names."
        ),
        mitigation=(
            "Block the request, or normalize and re-check: reject "
            "values containing characters from more than one script "
            "unless your application has a genuine need for mixed-"
            "script identity fields (rare for domains/usernames, more "
            "plausible for free-text display names in a "
            "multilingual product -- tune the field opt-in "
            "accordingly)."
        ),
        false_positive_notes=(
            "Opt-in per field, aimed at identity-like fields (domain, "
            "username, brand/company name) where script-mixing is "
            "almost always suspicious. Genuinely multilingual free-text "
            "fields (a bio, a comment) will false-positive constantly "
            "if this is enabled there -- enable with "
            "`aegis.field(route, field_name, homograph=True)` only on "
            "the narrow identity-field surface it's meant for."
        ),
        limitations=(
            "Covers a curated set of the most common Latin-lookalike "
            "Cyrillic/Greek characters, not the full Unicode confusables "
            "table (which includes many scripts and is large enough "
            "that a complete implementation belongs in a dedicated "
            "library, e.g. the Unicode Consortium's confusables data "
            "via a package like `confusable_homoglyphs`, for "
            "applications with a serious anti-spoofing requirement)."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "homograph", default=False):
                continue

            scripts_seen = {_script_of(ch) for ch in value if ch.isalpha()}
            has_confusable = any(ch in _CONFUSABLES for ch in value)

            if "LATIN" in scripts_seen and ({"CYRILLIC", "GREEK"} & scripts_seen) and has_confusable:
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.BLOCK,
                    message=f"Potential homograph/mixed-script spoofing in field '{field_name}'",
                    severity=self.meta.severity,
                    score=20,
                    meta={"field": field_name, "scripts": sorted(scripts_seen)},
                )
        return None
