"""
flask_aegis.rules.redos
~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-REDOS-001: Regular Expression Denial of Service (ReDoS) pattern
detection.

For applications that accept a user-supplied regular expression (a
search feature, a custom validation rule, a log-filter UI) and compile
it server-side, a pattern with catastrophic backtracking potential can
hang a worker thread on a short, otherwise-innocuous-looking input.
This rule flags the structural shapes known to cause catastrophic
backtracking in backtracking regex engines (Python's `re`, PCRE, .NET,
JavaScript): nested quantifiers, and alternation with overlapping
branches under a quantifier.

Opt-in per field, since most fields are never compiled as a regex.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

# Nested quantifiers: a quantified group containing another quantified
# atom, e.g. (a+)+, (a*)*, (a+)*, ([a-z]+)+  -- the classic
# exponential-blowup shape.
_NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)[+*]")

# Alternation with overlapping/identical branches under a quantifier,
# e.g. (a|a)+, (a|ab)*  -- also exponential in the worst case.
_OVERLAPPING_ALTERNATION = re.compile(r"\(([^()|]+)\|\1[^()]*\)[+*]")

# A quantified group immediately followed by another quantifier on an
# overlapping character class, e.g. (\d+)+\d, ([a-zA-Z]+)*[a-zA-Z]
_QUANTIFIER_CHAIN = re.compile(r"\([^()]*[+*]\)[+*]\s*[\w\\]")


class ReDoSRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-REDOS-001",
        category="redos",
        severity="high",
        description=(
            "Detects regular expression patterns with catastrophic "
            "backtracking potential: nested quantifiers ((a+)+, (a*)*), "
            "overlapping alternation under a quantifier ((a|a)+), and "
            "a quantified group immediately followed by an overlapping "
            "quantified atom -- the structural shapes that cause "
            "exponential-time matching in backtracking regex engines "
            "(Python re, PCRE, .NET, JavaScript) against a short, "
            "adversarially-chosen input."
        ),
        mitigation=(
            "Block the request. If your application genuinely needs to "
            "accept user-supplied regular expressions, compile them "
            "with a timeout (e.g. the `regex` package's timeout "
            "parameter, or run compilation/matching in a "
            "resource-limited subprocess) rather than relying on "
            "pattern-shape detection alone -- this rule catches known "
            "shapes, not every possible catastrophic pattern."
        ),
        false_positive_notes=(
            "This rule is opt-in per field, since most fields are never "
            "compiled as a regex at all. Enable with "
            "`aegis.field(route, field_name, redos=True)` only on "
            "fields your code actually passes to `re.compile()` or "
            "equivalent."
        ),
        limitations=(
            "Detects known catastrophic-backtracking *shapes*, not "
            "every pattern that could be slow -- a sufficiently obscure "
            "construction can still cause backtracking blowup without "
            "matching any of these heuristics. A compile-time timeout "
            "is the defense that doesn't depend on recognizing the "
            "pattern shape in advance."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "redos", default=False):
                continue
            for pattern, detail in (
                (_NESTED_QUANTIFIER, "nested quantifier"),
                (_OVERLAPPING_ALTERNATION, "overlapping alternation under a quantifier"),
                (_QUANTIFIER_CHAIN, "quantified group followed by an overlapping quantifier"),
            ):
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential ReDoS pattern ({detail}) in field '{field_name}'",
                        severity=self.meta.severity,
                        score=25,
                        meta={"field": field_name, "detail": detail},
                    )
        return None
