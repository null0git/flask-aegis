"""
flask_aegis.rules.engine_injection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Three narrow-surface "injection into a specific rendering/formatting
engine" rules, grouped together the same way misc_injection.py groups
header and CSV injection: each targets a specific downstream consumer
rather than a general-purpose language, so each is opt-in per field and
only meaningful on the routes that actually use that consumer.

- AEGIS-SSI-001: Server-Side Includes injection (legacy Apache/IIS
  `<!--#exec ...-->` directives) -- relevant if your stack serves any
  content through an SSI-enabled web server or template layer.
- AEGIS-LATEX-001: LaTeX injection -- relevant for report/PDF-generation
  features that interpolate user input into a `.tex` source before
  compiling it (a common pattern for invoice/certificate generators).
- AEGIS-FORMATSTR-001: C-style format string injection -- relevant if
  user input reaches a native `printf`-family call via a C extension,
  ctypes, or a Python `%`-style format applied to a string that
  originated from a request rather than a fixed template.
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_SSI_PATTERN = re.compile(r"<!--#\s*(exec|include|echo|config|fsize|flastmod)\b", re.IGNORECASE)

_LATEX_PATTERNS = [
    re.compile(r"\\write18"),
    re.compile(r"\\input\s*\{"),
    re.compile(r"\\include\s*\{"),
    re.compile(r"\\immediate\s*\\write"),
    re.compile(r"\\openout"),
    re.compile(r"\\catcode"),
]

# %n is the dangerous one (writes to memory in C's printf); a long run
# of %s/%x is the classic crash-and-leak probing pattern used to find
# a format-string vulnerability before exploiting it further.
_FORMAT_STRING_PATTERNS = [
    re.compile(r"%n"),
    re.compile(r"(%[sx]){4,}"),
    re.compile(r"%\d+\$"),  # positional format specifier, used in exploitation
]


class SSIInjectionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-SSI-001",
        category="ssi_injection",
        severity="high",
        description=(
            "Detects Server-Side Includes (SSI) injection: "
            "<!--#exec/include/echo/config/fsize/flastmod --> "
            "directives that an SSI-enabled web server or template "
            "layer would execute rather than display as literal text."
        ),
        mitigation=(
            "Block the request. Disable SSI processing on any endpoint "
            "that serves user-influenced content, or escape '<!--#' "
            "sequences before they reach an SSI-enabled response path."
        ),
        false_positive_notes=(
            "Opt-in per field -- most applications have no SSI-enabled "
            "response path at all, in which case this rule protects "
            "nothing and can be left disabled. Enable with "
            "`aegis.field(route, field_name, ssi_injection=True)` only "
            "where user input can reach SSI-processed output."
        ),
        limitations="Pattern-based; covers the standard SSI directive set only.",
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "ssi_injection", default=False):
                continue
            if _SSI_PATTERN.search(value):
                return Finding(
                    rule_id=self.meta.rule_id,
                    decision=Decision.BLOCK,
                    message=f"Potential SSI injection payload in field '{field_name}'",
                    severity=self.meta.severity,
                    score=25,
                    meta={"field": field_name},
                )
        return None


class LaTeXInjectionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-LATEX-001",
        category="latex_injection",
        severity="high",
        description=(
            "Detects LaTeX injection: \\write18 (shell escape), "
            "\\input/\\include (arbitrary file inclusion), "
            "\\openout/\\immediate\\write (arbitrary file write), and "
            "\\catcode (category-code manipulation used to smuggle "
            "further payloads past naive filters)."
        ),
        mitigation=(
            "Block the request. If your application compiles "
            "user-influenced LaTeX (report/certificate/invoice "
            "generation), compile with shell-escape disabled "
            "(the default in most distributions unless explicitly "
            "enabled) and in a sandboxed working directory with no "
            "sensitive files reachable."
        ),
        false_positive_notes=(
            "Opt-in per field -- only meaningful for routes that "
            "actually interpolate input into LaTeX source before "
            "compiling it. Enable with "
            "`aegis.field(route, field_name, latex_injection=True)`."
        ),
        limitations="Pattern-based; covers the commonly-exploited LaTeX primitives only.",
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "latex_injection", default=False):
                continue
            for pattern in _LATEX_PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential LaTeX injection payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=25,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None


class FormatStringRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-FORMATSTR-001",
        category="format_string",
        severity="high",
        description=(
            "Detects C-style format string injection: %n (writes to "
            "memory -- the primitive behind format-string exploitation), "
            "long runs of %s/%x (the classic crash-and-probe pattern "
            "used to find a vulnerable printf-family call), and "
            "positional specifiers (%1$s) commonly used once a "
            "vulnerability is confirmed."
        ),
        mitigation=(
            "Block the request. Never pass request-derived data as the "
            "*format string* argument to a printf-family function "
            "(C code reached via ctypes/cffi, or a native extension) -- "
            "pass it as a value argument to a fixed format string "
            "instead."
        ),
        false_positive_notes=(
            "Opt-in per field -- only meaningful if user input can "
            "reach a native printf-family call. Pure-Python string "
            "formatting (%-formatting, .format(), f-strings) is not "
            "vulnerable to this class at all; enable this rule only on "
            "fields that specifically flow into native code."
        ),
        limitations="Pattern-based; a sufficiently obfuscated format string can still evade these heuristics.",
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "format_string", default=False):
                continue
            for pattern in _FORMAT_STRING_PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential format string injection payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=25,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None
