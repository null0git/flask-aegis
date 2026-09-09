"""
flask_aegis.decisions
~~~~~~~~~~~~~~~~~~~~~~

The decision engine turns rule findings + a risk score into one final
action. Rules never block a request directly — they report a finding,
and the DecisionEngine decides what to do about it. This separation is
what lets Flask-Aegis run in "monitor" mode: the same rules fire, but
the engine is told to never escalate past LOG.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Decision(enum.IntEnum):
    """Ordered from least to most severe so decisions can be combined
    with ``max()``. A single request may accumulate several findings;
    the highest-severity decision wins."""

    ALLOW = 0
    LOG = 1
    SANITIZE = 2
    THROTTLE = 3
    CHALLENGE = 4
    BLOCK = 5

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Finding:
    """A single piece of evidence produced by a rule or the risk engine."""

    rule_id: str
    decision: Decision
    message: str
    severity: str = "medium"
    score: int = 0
    meta: dict = field(default_factory=dict)


@dataclass
class Verdict:
    """The final, aggregated outcome of the security pipeline for one request."""

    decision: Decision
    findings: list = field(default_factory=list)
    risk_score: int = 0

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    @property
    def rule_ids(self) -> list:
        return [f.rule_id for f in self.findings]

    def top_finding(self) -> Optional[Finding]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.decision)


class DecisionEngine:
    """Combines findings from rules + risk score into a final :class:`Verdict`,
    respecting the extension's enforcement mode.

    Modes
    -----
    enforce   - the decision from findings/risk is applied as-is.
    monitor   - findings are recorded but the effective decision is capped
                at LOG, so nothing is ever blocked or challenged.
    adaptive  - like enforce, but the risk engine is allowed to *upgrade*
                a low-severity finding (e.g. LOG -> CHALLENGE) based on
                the accumulated risk score for the request.
    """

    def __init__(self, mode: str = "enforce"):
        if mode not in ("enforce", "monitor", "adaptive"):
            raise ValueError(f"Unknown enforcement mode: {mode!r}")
        self.mode = mode

    def resolve(self, findings: list, risk_score: int = 0) -> Verdict:
        if not findings:
            return Verdict(decision=Decision.ALLOW, findings=[], risk_score=risk_score)

        decision = max(f.decision for f in findings)

        if self.mode == "monitor":
            decision = min(decision, Decision.LOG)
        elif self.mode == "adaptive":
            decision = self._adapt(decision, risk_score)

        return Verdict(decision=decision, findings=findings, risk_score=risk_score)

    @staticmethod
    def _adapt(decision: Decision, risk_score: int) -> Decision:
        """Let accumulated risk push a borderline decision up or down by
        one step. This is intentionally conservative: adaptive mode never
        jumps straight from LOG to BLOCK — it escalates one tier at a time
        so a single noisy rule can't cause a hard outage."""
        if risk_score >= 90 and decision < Decision.CHALLENGE:
            return Decision.CHALLENGE
        if risk_score >= 60 and decision < Decision.THROTTLE:
            return Decision.THROTTLE
        return decision
