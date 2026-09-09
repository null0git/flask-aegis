"""
flask_aegis.rulesets
~~~~~~~~~~~~~~~~~~~~~~

Versioned rule sets: which detection rules exist under a given ruleset
name. This exists so security rules can evolve (new rules added, existing
ones tightened) without silently changing the behavior of an application
that hasn't opted in -- pin ``Aegis(app, ruleset="2025-baseline")`` and
new rule additions in later Flask-Aegis releases won't suddenly start
firing on routes that were never audited against them.

A ruleset controls *which rule classes exist*, not their individual
tuning (severity, patterns) -- those still evolve within a rule's
lifetime via normal version upgrades of the package itself. Ruleset
pinning is for the coarser question of "should this new rule apply to
my app at all yet."

Add a new ruleset by adding an entry to ``RULESETS`` and, when it
represents the new default, repointing ``"latest"`` at it.
"""
from __future__ import annotations

from .exceptions import ConfigurationError
from .rules.base import RuleRegistry
from .rules.cmdi import CommandInjectionRule
from .rules.deserialization import DeserializationRule
from .rules.el_injection import ELInjectionRule
from .rules.engine_injection import FormatStringRule, LaTeXInjectionRule, SSIInjectionRule
from .rules.homograph import HomographRule
from .rules.hpp import ParameterPollutionRule
from .rules.jwt_weak import JWTWeakAlgorithmRule
from .rules.ldap_xpath import LDAPInjectionRule, XPathInjectionRule
from .rules.mass_assignment import MassAssignmentRule
from .rules.misc_injection import CSVInjectionRule, HeaderInjectionRule
from .rules.nosqli import NoSQLInjectionRule
from .rules.open_redirect import OpenRedirectRule
from .rules.proto_pollution import PrototypePollutionRule
from .rules.redos import ReDoSRule
from .rules.sqli import SQLiRule
from .rules.ssrf_field import SSRFFieldRule
from .rules.ssti import SSTIRule
from .rules.traversal import TraversalRule
from .rules.xml_bomb import XMLBombRule
from .rules.xss import XSSRule
from .rules.xxe import XXERule

# The original three rules Flask-Aegis shipped with (Phase 1). Pin to
# this if you audited your app against exactly this set and want new
# rule additions to require an explicit, deliberate upgrade rather than
# arriving silently with a `pip install --upgrade`.
_BASELINE_2025 = [XSSRule, SQLiRule, TraversalRule]

# Phase 1 + Phase 2: adds SSTI, command/LDAP/XPath injection, header and
# CSV injection. Frozen at this set -- later additions get a new entry
# below rather than silently expanding this one, so an app pinned to
# "2026" keeps exactly this rule surface forever.
_FULL_2026 = _BASELINE_2025 + [
    SSTIRule, CommandInjectionRule, LDAPInjectionRule, XPathInjectionRule,
    HeaderInjectionRule, CSVInjectionRule,
]

# Phase 4a: adds NoSQL injection, XXE, open redirect, and HTTP Parameter
# Pollution detection. Also frozen at this set.
_FULL_2027 = _FULL_2026 + [
    NoSQLInjectionRule, XXERule, OpenRedirectRule, ParameterPollutionRule,
]

# Phase 4b: adds insecure deserialization, request-field SSRF detection,
# prototype pollution, and Expression Language (Java/Spring EL, OGNL)
# injection. Also frozen at this set.
_FULL_2028 = _FULL_2027 + [
    DeserializationRule, SSRFFieldRule, PrototypePollutionRule, ELInjectionRule,
]

# Phase 4c: adds mass assignment, ReDoS pattern detection, JWT
# weak-algorithm detection, homograph/mixed-script spoofing, XML entity
# expansion bombs, and SSI/LaTeX/format-string injection.
_FULL_2029 = _FULL_2028 + [
    MassAssignmentRule, ReDoSRule, JWTWeakAlgorithmRule, HomographRule,
    XMLBombRule, SSIInjectionRule, LaTeXInjectionRule, FormatStringRule,
]

RULESETS = {
    "2025-baseline": _BASELINE_2025,
    "2026": _FULL_2026,
    "2027": _FULL_2027,
    "2028": _FULL_2028,
    "2029": _FULL_2029,
}
RULESETS["latest"] = RULESETS["2029"]


def build_registry(ruleset: str = "latest") -> RuleRegistry:
    """Build a :class:`~flask_aegis.rules.base.RuleRegistry` containing
    exactly the rule classes assigned to ``ruleset``. Raises
    :class:`~flask_aegis.exceptions.ConfigurationError` for an unknown
    name rather than silently falling back to a default -- a typo'd
    ruleset name should fail loudly at startup, not quietly under-protect
    the app."""
    if ruleset not in RULESETS:
        raise ConfigurationError(
            f"Unknown ruleset {ruleset!r}. Available rulesets: "
            f"{', '.join(sorted(RULESETS))}"
        )
    registry = RuleRegistry()
    for rule_cls in RULESETS[ruleset]:
        registry.register(rule_cls())
    return registry


def list_rulesets() -> dict:
    """Returns {ruleset_name: [rule_id, ...]} for every registered
    ruleset, e.g. for `flask aegis ruleset list`."""
    return {
        name: [cls().meta.rule_id for cls in classes]
        for name, classes in RULESETS.items()
    }
