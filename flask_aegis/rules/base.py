"""
flask_aegis.rules.base
~~~~~~~~~~~~~~~~~~~~~~~~

Base class every detection rule implements, plus the registry used to
look rules up by their stable identifier (e.g. ``AEGIS-XSS-001``).

Every rule ships with structured metadata (severity, category, description)
so that ``flask aegis rules`` and the audit report can describe *why*
something fired without the operator needing to read source code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from ..decisions import Decision, Finding


@dataclass
class RuleMeta:
    rule_id: str
    category: str
    severity: str  # low | medium | high | critical
    description: str
    mitigation: str
    false_positive_notes: str = ""
    limitations: str = ""


class Rule:
    """Base class for a Flask-Aegis detection rule.

    Subclasses implement :meth:`check`, which receives the normalized
    request context and either returns ``None`` (no finding) or a
    :class:`~flask_aegis.decisions.Finding`.

    Rules must never raise on attacker-controlled input — a malformed
    payload is a *finding*, not a Python exception. Only genuine internal
    bugs should raise, and those should be :class:`~flask_aegis.exceptions.RuleError`.
    """

    meta: ClassVar[RuleMeta]

    def applies_to(self, ctx) -> bool:
        """Cheap pre-check so expensive rules can skip requests that
        obviously don't apply (e.g. a body-scanning rule skipping GET
        requests with no body). Default: always applies."""
        return True

    def check(self, ctx) -> Optional[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


class RuleRegistry:
    """Holds the active set of rules, keyed by rule_id, and lets policies
    enable/disable them by category (``xss``, ``sqli``, ``traversal``, ...)."""

    def __init__(self):
        self._rules: dict[str, Rule] = {}
        self._by_category: dict[str, list] = {}

    def register(self, rule: Rule) -> None:
        self._rules[rule.meta.rule_id] = rule
        self._by_category.setdefault(rule.meta.category, []).append(rule)

    def get(self, rule_id: str) -> Rule:
        return self._rules[rule_id]

    def for_category(self, category: str) -> list:
        return list(self._by_category.get(category, []))

    def categories(self) -> list:
        """All distinct category names currently registered, including
        ones added by third-party rules via `register_detector()` --
        used by the pipeline to discover plugin categories that aren't
        in the fixed `RULE_CATEGORY_FIELDS` set."""
        return list(self._by_category.keys())

    def all(self) -> list:
        return list(self._rules.values())
