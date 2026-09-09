"""
flask_aegis.events
~~~~~~~~~~~~~~~~~~~~

Structured security events + a minimal pub/sub bus, plus automatic
redaction of sensitive fields before an event is handed to any listener
(including your own logger).

Example
-------
>>> @aegis.on("security_event")
... def handle(event):
...     logger.warning("aegis: %s", event)
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Callable

_REDACT_KEYS = {
    "password", "passwd", "secret", "secret_key", "token", "api_key",
    "apikey", "authorization", "cookie", "session", "csrf_token",
    "captcha_secret",
}
_REDACTED = "***REDACTED***"


def redact(value):
    """Recursively redact known-sensitive keys from a dict/list structure
    before it is logged or emitted to a listener."""
    if isinstance(value, dict):
        return {
            k: (_REDACTED if k.lower() in _REDACT_KEYS else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


@dataclass
class SecurityEvent:
    event: str
    route: str
    severity: str
    action: str
    rule: str | None = None
    risk_score: int = 0
    timestamp: float = field(default_factory=time.time)
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["meta"] = redact(d["meta"])
        return d


class EventBus:
    """Minimal synchronous pub/sub bus. Listeners are called in
    registration order; an exception in one listener is isolated so it
    can't break request handling or prevent other listeners from running."""

    def __init__(self):
        self._listeners: dict[str, list[Callable]] = {}

    def on(self, event_name: str):
        def decorator(fn: Callable):
            self._listeners.setdefault(event_name, []).append(fn)
            return fn
        return decorator

    def emit(self, event_name: str, payload) -> None:
        for fn in self._listeners.get(event_name, []):
            try:
                fn(payload)
            except Exception:  # noqa: BLE001 - isolate listener failures
                import logging
                logging.getLogger("flask_aegis").exception(
                    "Unhandled exception in security_event listener %r", fn
                )
