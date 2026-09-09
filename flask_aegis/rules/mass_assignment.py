"""
flask_aegis.rules.mass_assignment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-MASSASSIGN-001: mass assignment detection.

Flags request bodies containing keys that name a privileged or
internal attribute (role, is_admin, permissions, password_hash, ...)
that a naive handler might blindly assign onto a model
(`User(**request.json)`, `user.__dict__.update(request.json)`,
an ORM's `.update(**data)`) without an explicit allowlist of assignable
fields.

Configured with a route-level list of sensitive key names, since this
rule is keyed by field *name* rather than content.
"""
from __future__ import annotations

from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_DEFAULT_SENSITIVE_KEYS = {
    "role", "roles", "is_admin", "isadmin", "admin", "is_staff", "is_superuser",
    "permissions", "permission", "scopes", "scope", "password_hash", "passwordhash",
    "verified", "is_verified", "email_verified", "account_type", "balance",
    "credit", "credits", "user_id", "owner_id", "tenant_id", "organization_id",
}


class MassAssignmentRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-MASSASSIGN-001",
        category="mass_assignment",
        severity="high",
        description=(
            "Flags request bodies (form or JSON) that include a key "
            "naming a privileged or internal attribute -- role, "
            "is_admin, permissions, password_hash, balance, and similar "
            "-- that a handler assigning fields in bulk "
            "(Model(**request.json), object.__dict__.update(data)) "
            "could set without an explicit allowlist."
        ),
        mitigation=(
            "Block the request, or better: never construct/update a "
            "model from a raw request dict. Build an explicit allowlist "
            "of assignable fields per endpoint (a dataclass, a "
            "marshmallow/pydantic schema with only the intended fields) "
            "and copy values across field-by-field."
        ),
        false_positive_notes=(
            "The sensitive-key list is necessarily generic -- a "
            "legitimate admin-management endpoint needs to accept "
            "'role' or 'permissions' as real, intended input. Configure "
            "the actual sensitive-key set per route with "
            "`aegis.field(route, field_name, mass_assignment=False)` "
            "for fields that are legitimately assignable on that route, "
            "or disable the category entirely where it doesn't apply."
        ),
        limitations=(
            "Name-based, not schema-based -- it flags a key existing in "
            "the body, not whether your code actually assigns it "
            "unsafely. A route that already validates against an "
            "explicit schema gets no benefit from this rule and can "
            "disable it; a route with no such validation is exactly "
            "where this rule earns its keep."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name in ctx.text_values:
            if not ctx.field_option(field_name, "mass_assignment", default=True):
                continue
            if field_name.lower() in _DEFAULT_SENSITIVE_KEYS:
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.BLOCK,
                    message=f"Potential mass assignment: sensitive key '{field_name}' present in request body",
                    severity=self.meta.severity,
                    score=25,
                    meta={"field": field_name},
                )
        return None
