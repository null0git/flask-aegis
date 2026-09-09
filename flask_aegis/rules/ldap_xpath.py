"""
flask_aegis.rules.ldap_xpath
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AEGIS-LDAP-001 and AEGIS-XPATH-001: heuristic detection for LDAP and
XPath injection. These are grouped in one module because both are
filter/query languages where injection hinges on unescaped metacharacters
(parentheses and boolean operators for LDAP; quotes and axis syntax for
XPath), and applications frequently need both checks together (e.g. an
LDAP-backed directory exposed through an XML-configured search API).
"""
from __future__ import annotations

import re
from typing import Optional

from ..decisions import Decision, Finding
from .base import Rule, RuleMeta

_LDAP_PATTERNS = [
    re.compile(r"\(\s*[|&]\s*\("),                 # (|(...)) or (&(...))
    re.compile(r"\)\s*\(\s*\w+\s*=\s*\*\s*\)"),      # )(uid=*)
    re.compile(r"\*\)\s*\(\s*\w"),                    # *)(...
    re.compile(r"\\28|\\29|\\2a"),                      # hex-escaped ( ) *
]

_XPATH_PATTERNS = [
    re.compile(r"'\s*or\s*'1'\s*=\s*'1", re.IGNORECASE),
    re.compile(r"'\s*or\s*'\s*'\s*=\s*'", re.IGNORECASE),
    re.compile(r"\]\s*\|\s*//"),                     # ] | //
    re.compile(r"//\*\[.*?\]"),                       # //*[...]
    re.compile(r"count\s*\(\s*/\s*\*\s*\)", re.IGNORECASE),
]


class LDAPInjectionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-LDAP-001",
        category="ldap",
        severity="high",
        description=(
            "Detects LDAP filter injection: boolean filter chaining "
            "((|(...)), (&(...))), wildcard-based attribute injection "
            "((uid=*)), and hex-escaped metacharacters used to bypass "
            "naive filtering."
        ),
        mitigation=(
            "Block the request. Use a proper LDAP filter-escaping "
            "function (e.g. `ldap3.utils.conv.escape_filter_chars`) "
            "rather than string concatenation when building filters."
        ),
        false_positive_notes=(
            "Rare outside of directory-search endpoints; enable this "
            "category specifically on routes that build LDAP filters "
            "rather than globally."
        ),
        limitations="Pattern-based; does not parse the actual LDAP filter grammar.",
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "ldap", default=True):
                continue
            for pattern in _LDAP_PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential LDAP injection payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=25,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None


class XPathInjectionRule(Rule):
    meta = RuleMeta(
        rule_id="AEGIS-XPATH-001",
        category="xpath",
        severity="high",
        description=(
            "Detects XPath injection: boolean tautologies ('or '1'='1), "
            "union-style node-set combination (] | //), wildcard axis "
            "injection (//*[...]), and count()-based blind probing."
        ),
        mitigation=(
            "Block the request. Use parameterized XPath (e.g. XPath "
            "variables via `lxml.etree.XPath` with a variables dict) "
            "instead of string-built expressions."
        ),
        false_positive_notes=(
            "Rare outside of XML-search endpoints; enable this category "
            "specifically on routes that evaluate user-influenced XPath."
        ),
        limitations="Pattern-based; does not parse the actual XPath grammar.",
    )

    def applies_to(self, ctx) -> bool:
        return bool(ctx.text_values)

    def check(self, ctx) -> Optional[Finding]:
        for field_name, value in ctx.text_values.items():
            if not ctx.field_option(field_name, "xpath", default=True):
                continue
            for pattern in _XPATH_PATTERNS:
                if pattern.search(value):
                    return Finding(
                        rule_id=self.meta.rule_id,
                        decision=Decision.BLOCK,
                        message=f"Potential XPath injection payload in field '{field_name}'",
                        severity=self.meta.severity,
                        score=25,
                        meta={"field": field_name, "pattern": pattern.pattern},
                    )
        return None
