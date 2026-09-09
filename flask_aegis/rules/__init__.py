"""
flask_aegis.rules
~~~~~~~~~~~~~~~~~~

Built-in detection rules and the registry that holds them.

Third-party rules can be added with ``aegis.register_detector(MyRule())``
(see plugins.py) — they show up in ``flask aegis rules`` alongside the
built-ins as long as they subclass :class:`~flask_aegis.rules.base.Rule`.
"""
from .base import Rule, RuleMeta, RuleRegistry
from .cmdi import CommandInjectionRule
from .deserialization import DeserializationRule
from .el_injection import ELInjectionRule
from .engine_injection import FormatStringRule, LaTeXInjectionRule, SSIInjectionRule
from .homograph import HomographRule
from .hpp import ParameterPollutionRule
from .jwt_weak import JWTWeakAlgorithmRule
from .ldap_xpath import LDAPInjectionRule, XPathInjectionRule
from .mass_assignment import MassAssignmentRule
from .misc_injection import CSVInjectionRule, HeaderInjectionRule
from .nosqli import NoSQLInjectionRule
from .open_redirect import OpenRedirectRule
from .proto_pollution import PrototypePollutionRule
from .redos import ReDoSRule
from .sqli import SQLiRule
from .ssrf_field import SSRFFieldRule
from .ssti import SSTIRule
from .traversal import TraversalRule, safe_join_root
from .xml_bomb import XMLBombRule
from .xss import XSSRule
from .xxe import XXERule


def default_registry() -> RuleRegistry:
    """Build a :class:`RuleRegistry` with all built-in rules registered.
    Called once by ``Aegis.init_app`` unless the user supplies their own."""
    registry = RuleRegistry()
    registry.register(XSSRule())
    registry.register(SQLiRule())
    registry.register(TraversalRule())
    registry.register(SSTIRule())
    registry.register(CommandInjectionRule())
    registry.register(LDAPInjectionRule())
    registry.register(XPathInjectionRule())
    registry.register(HeaderInjectionRule())
    registry.register(CSVInjectionRule())
    registry.register(NoSQLInjectionRule())
    registry.register(XXERule())
    registry.register(OpenRedirectRule())
    registry.register(ParameterPollutionRule())
    registry.register(DeserializationRule())
    registry.register(SSRFFieldRule())
    registry.register(PrototypePollutionRule())
    registry.register(ELInjectionRule())
    registry.register(MassAssignmentRule())
    registry.register(ReDoSRule())
    registry.register(JWTWeakAlgorithmRule())
    registry.register(HomographRule())
    registry.register(XMLBombRule())
    registry.register(SSIInjectionRule())
    registry.register(LaTeXInjectionRule())
    registry.register(FormatStringRule())
    return registry


__all__ = [
    "Rule", "RuleMeta", "RuleRegistry", "default_registry",
    "XSSRule", "SQLiRule", "TraversalRule", "safe_join_root",
    "SSTIRule", "CommandInjectionRule", "LDAPInjectionRule",
    "XPathInjectionRule", "HeaderInjectionRule", "CSVInjectionRule",
    "NoSQLInjectionRule", "XXERule", "OpenRedirectRule", "ParameterPollutionRule",
    "DeserializationRule", "SSRFFieldRule", "PrototypePollutionRule", "ELInjectionRule",
    "MassAssignmentRule", "ReDoSRule", "JWTWeakAlgorithmRule", "HomographRule",
    "XMLBombRule", "SSIInjectionRule", "LaTeXInjectionRule", "FormatStringRule",
]
