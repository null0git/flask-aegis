"""
flask_aegis.rules.hpp
~~~~~~~~~~~~~~~~~~~~~~

AEGIS-HPP-001: HTTP Parameter Pollution detection.

Flags a query-string or form field submitted more than once with
different values -- the classic HPP primitive, exploitable when
different layers of an application stack (a WAF, the app framework, a
downstream service) disagree about which of several same-named values
"wins." Flask/Werkzeug takes the *first* value for `request.args.get()`,
but code that reads `request.args.getlist()` or forwards the raw query
string to another service may disagree, which is exactly the
inconsistency HPP attacks exploit.

Unlike the other rules, this doesn't operate on a single flattened value
-- see RequestContext.duplicate_params, populated directly from the
request's multidicts.
"""
from __future__ import annotations

from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta


class ParameterPollutionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-HPP-001",
        category="hpp",
        severity="medium",
        description=(
            "Detects HTTP Parameter Pollution: a query-string or form "
            "field submitted more than once with different values. "
            "Different components of an application stack (framework, "
            "downstream service, logging/analytics) can disagree about "
            "which duplicate 'wins', which is the exploitable "
            "inconsistency this pattern creates."
        ),
        mitigation=(
            "Block the request, or explicitly decide and document which "
            "value your application uses for a given field name and "
            "ensure every layer that reads it (validation, business "
            "logic, logging, any downstream service you proxy the "
            "request to) agrees. Never assume 'the app framework already "
            "decided' is true for every consumer of the request."
        ),
        false_positive_notes=(
            "Some fields are legitimately meant to be repeated (e.g. "
            "`tags=a&tags=b&tags=c` for a multi-select) -- this rule "
            "only flags a name when its *values differ*, and even then "
            "you should exempt known multi-value fields explicitly with "
            "`aegis.field(route, field_name, hpp=False)`."
        ),
        limitations=(
            "Only inspects query-string and form-encoded duplicates -- "
            "does not inspect duplicate keys within a JSON body (which "
            "isn't even syntactically valid JSON in the first place) or "
            "duplicate HTTP headers, which is a related but distinct "
            "class of pollution this rule doesn't cover."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.duplicate_params)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, values in ctx.duplicate_params.items():
            if not ctx.field_option(field_name, "hpp", default=True):
                continue
            return Finding(
                rule_id=self.meta.rule_id,
                decision=Decision.BLOCK,
                message=f"Parameter '{field_name}' submitted multiple times with different values",
                severity=self.meta.severity,
                score=15,
                meta={"field": field_name, "values": values},
            )
        return None
