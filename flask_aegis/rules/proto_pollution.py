"""
flask_aegis.rules.proto_pollution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-PROTO-001: prototype pollution detection.

Prototype pollution is primarily a JavaScript/Node.js vulnerability
class, but a Flask backend is a common producer of the JSON payload
that eventually reaches a vulnerable JS consumer -- a Node-based
frontend build step, a serverless function written in JS, a browser
client that merges the API response into its own state with a
vulnerable deep-merge/clone utility (an old lodash.merge, a hand-rolled
recursive Object.assign). This rule flags the injection primitive
(`__proto__`, `constructor.prototype`) in *request* input so it never
reaches your own JSON body in the first place -- your API can be the
origin of a payload that pollutes a downstream JS consumer's runtime
even if your own Python backend never touches a prototype.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_PATTERNS = [
    re.compile(r"__proto__"),
    re.compile(r"constructor\s*\.\s*prototype"),
    re.compile(r"constructor\s*\[\s*['\"]prototype['\"]\s*\]"),
    re.compile(r"prototype\s*\.\s*constructor"),
]


class PrototypePollutionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-PROTO-001",
        category="proto_pollution",
        severity="high",
        description=(
            "Detects prototype pollution primitives ('__proto__', "
            "'constructor.prototype', bracket-notation equivalents) in "
            "request input -- keys or values that, if merged into a "
            "JavaScript object by a vulnerable deep-merge/clone utility "
            "downstream (in your own Node tooling or a client "
            "consuming your API's JSON), let an attacker inject "
            "properties onto Object.prototype itself."
        ),
        mitigation=(
            "Block the request. Independently: if any part of your "
            "stack (a Node-based build step, a JS frontend, a "
            "serverless function) deep-merges request-derived data into "
            "an object, use a merge utility with prototype-pollution "
            "protection (current lodash, or Object.create(null) as the "
            "merge target), and never recurse into keys named "
            "'__proto__', 'constructor', or 'prototype'."
        ),
        false_positive_notes=(
            "A field discussing JavaScript/prototypal inheritance in "
            "free text (documentation, a support ticket, a code-review "
            "comment) will trigger this. Exempt with "
            "`aegis.field(route, field_name, proto_pollution=False)` "
            "for known free-text technical fields."
        ),
        limitations=(
            "This is a Python backend rule flagging the *input* "
            "primitive -- it cannot know whether anything downstream "
            "actually merges this value unsafely, or whether your stack "
            "has a JS component at all. If your application is pure "
            "Python with no JS consumer of its output anywhere, this "
            "rule protects nothing and can be safely disabled."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "proto_pollution", default=True):
                continue
            for pattern in _PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential prototype pollution payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=25,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None
