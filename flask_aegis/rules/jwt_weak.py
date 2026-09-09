"""
flask_aegis.rules.jwt_weak
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-JWT-001: JWT weak/dangerous algorithm detection.

Flags a JWT (JSON Web Token) whose header declares the "none" algorithm
or omits `alg` entirely -- the classic JWT signature-bypass
vulnerability, where a library configured to accept whatever algorithm
the token itself claims will treat an unsigned token as valid.

This is a request-time input check -- it inspects a JWT-*shaped* string
wherever one appears in the request (an Authorization header, a form
field, a cookie), not a replacement for your JWT library's own
verification. The actually-correct defense is to hardcode the expected
algorithm on the verifying side (`jwt.decode(token, key,
algorithms=["RS256"])`, never accepting whatever `alg` the token
claims) -- this rule catches a token that never should have been
accepted in the first place, before it reaches that code.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_JWT_SHAPE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_DANGEROUS_ALGS = {"none", ""}


def _decode_segment(segment: str) -> Optional[dict]:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except Exception:  # noqa: BLE001 -- not a valid JWT header, not our concern
        return None


class JWTWeakAlgorithmRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-JWT-001",
        category="jwt_weak",
        severity="critical",
        description=(
            "Detects a JWT whose header declares the 'none' algorithm "
            "or omits 'alg' entirely (the classic unsigned-token "
            "signature-bypass), found in any request value that has "
            "the three-segment, base64url JWT shape -- an Authorization "
            "header, a form field, or a cookie value."
        ),
        mitigation=(
            "Block the request. Independently: your JWT verification "
            "must hardcode the expected algorithm "
            "(`jwt.decode(token, key, algorithms=['RS256'])`), never "
            "read `alg` from the token and use it to decide how to "
            "verify -- that pattern is what makes both the 'none' "
            "bypass and algorithm-confusion attacks possible in the "
            "first place."
        ),
        false_positive_notes=(
            "Extremely low false-positive rate -- a legitimately-issued "
            "JWT from a correctly configured signer will never declare "
            "'none'. If your application has a genuine reason to accept "
            "unsigned tokens on a specific route (rare), disable this "
            "rule there explicitly rather than broadly."
        ),
        limitations=(
            "Only catches the 'none'/missing algorithm case, not "
            "algorithm-confusion attacks that use a nominally valid "
            "algorithm (that class of attack is a verification-side bug "
            "in accepting a different algorithm family than expected, "
            "which this rule cannot see from the token alone). Does not "
            "verify the token's signature -- signature verification is "
            "your JWT library's job, not this rule's."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values) or bool(ctx.headers.get("Authorization"))

    def check(self, ctx) -> Optional[Finding]:
        candidates = dict(ctx.text_values)
        auth_header = ctx.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            candidates["__authorization_header__"] = auth_header[7:].strip()

        for field_name, value in candidates.items():
            if not ctx.field_option(field_name, "jwt_weak", default=True):
                continue
            token = value.strip()
            if not _JWT_SHAPE.match(token):
                continue

            header_segment = token.split(".", 1)[0]
            header = _decode_segment(header_segment)
            if header is None:
                continue

            alg = header.get("alg")
            if alg is None or str(alg).lower() in _DANGEROUS_ALGS:
                display_field = "Authorization header" if field_name == "__authorization_header__" else field_name
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.BLOCK,
                    message=f"JWT with dangerous algorithm ({alg!r}) in {display_field}",
                    severity=self.meta.severity,
                    score=30,
                    meta={"field": field_name, "alg": alg},
                )
        return None
