"""
flask_aegis.rules.cmdi
~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-CMD-001: OS command injection heuristic detection.

Flags shell metacharacters and common command-chaining patterns in
request input. As with the other injection rules, this is a signal, not
a substitute for never passing user input to a shell — use
`subprocess.run([...], shell=False)` with an argument list, not a shell
string, wherever user input is involved.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_PATTERNS = [
    re.compile(r"[;&|`]\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh|python|perl|ruby|powershell|cmd)\b", re.IGNORECASE),
    re.compile(r"\$\(.+?\)"),                        # $(command)
    re.compile(r"`[^`]+`"),                          # `command`
    re.compile(r"\|\|\s*\w"),                          # || whoami
    re.compile(r"&&\s*\w"),                             # && whoami
    re.compile(r">\s*/dev/(null|tcp)"),                   # redirection to device
    re.compile(r"\b(nslookup|ping)\s+-[a-z]*\s*\d"),         # blind cmdi probing
]


class CommandInjectionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-CMD-001",
        category="cmdi",
        severity="critical",
        description=(
            "Detects OS command injection patterns: shell metacharacter "
            "chaining (;, &&, ||, |), command substitution ($(...), "
            "backticks), and common post-exploitation commands appended "
            "to input (whoami, cat, wget, nc, bash)."
        ),
        mitigation=(
            "Block the request. Independently, never build a shell "
            "command string from user input — use `subprocess.run` with "
            "an argument list and `shell=False`, and validate/allowlist "
            "any value that must be passed to an external program."
        ),
        false_positive_notes=(
            "Fields discussing shell syntax in documentation or code "
            "(e.g. a support ticket pasting a command) will trigger this "
            "rule. Exempt with `aegis.field(route, field_name, cmdi=False)` "
            "for known free-text technical fields."
        ),
        limitations=(
            "Cannot detect injection into non-shell contexts (e.g. "
            "argument injection into a program invoked without a shell), "
            "or injection that occurs via a stored value used later by a "
            "background job."
        ),
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "cmdi", default=True):
                continue
            for pattern in _PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential command injection payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=30,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None
