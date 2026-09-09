"""
flask_aegis.risk
~~~~~~~~~~~~~~~~~

A small, configurable additive risk scoring engine.

Design note: this is deliberately simple (sum of weighted signals, then
bucketed into a severity band) rather than a black-box model. Explainability
is a first-class requirement for Flask-Aegis — every score must be traceable
back to the exact signals that produced it, so operators can tune thresholds
and diagnose false positives.
"""
from __future__ import annotations

from dataclasses import dataclass, field


DEFAULT_WEIGHTS = {
    "suspicious_input": 20,
    "rate_limit_violation": 30,
    "repeated_failure": 15,
    "suspicious_url": 30,
    "invalid_captcha": 25,
    "known_bad_ua": 20,
    "new_identity": 10,
}

DEFAULT_THRESHOLDS = (
    (0, 29, "LOW"),
    (30, 59, "MEDIUM"),
    (60, 89, "HIGH"),
    (90, None, "CRITICAL"),
)


@dataclass
class RiskSignal:
    name: str
    weight: int
    meta: dict = field(default_factory=dict)


class RiskEngine:
    """Accumulates :class:`RiskSignal` objects for a single request and
    produces a final score + severity band.

    Example
    -------
    >>> engine = RiskEngine()
    >>> ctx = engine.new_context()
    >>> ctx.add("rate_limit_violation")
    >>> ctx.add("suspicious_input", meta={"field": "email"})
    >>> ctx.score
    50
    >>> ctx.band
    'MEDIUM'
    """

    def __init__(self, weights: dict | None = None, thresholds=None):
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        self.thresholds = thresholds or DEFAULT_THRESHOLDS

    def band_for(self, score: int) -> str:
        for low, high, name in self.thresholds:
            if high is None:
                if score >= low:
                    return name
            elif low <= score <= high:
                return name
        return "LOW"

    def new_context(self) -> "RiskContext":
        return RiskContext(engine=self)


@dataclass
class RiskContext:
    """Per-request accumulator returned by :meth:`RiskEngine.new_context`."""

    engine: RiskEngine
    signals: list = field(default_factory=list)

    def add(self, name: str, weight: int | None = None, **meta) -> None:
        w = weight if weight is not None else self.engine.weights.get(name, 10)
        self.signals.append(RiskSignal(name=name, weight=w, meta=meta))

    @property
    def score(self) -> int:
        return min(sum(s.weight for s in self.signals), 100)

    @property
    def band(self) -> str:
        return self.engine.band_for(self.score)

    def explain(self) -> list:
        """Return a human-readable breakdown of how the score was reached —
        used by ``flask aegis events`` and error responses in debug mode."""
        return [
            {"signal": s.name, "weight": s.weight, "meta": s.meta}
            for s in self.signals
        ]
