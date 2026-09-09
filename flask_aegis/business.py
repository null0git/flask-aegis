"""
flask_aegis.business
~~~~~~~~~~~~~~~~~~~~~~

Business-logic protection: per-user/action quotas, replay (duplicate
operation) protection, and action-frequency limiting. This is intentionally
a separate, standalone decorator (`@aegis.protect_action(...)`) rather than
part of the main `protect()` request pipeline, since business rules are
scoped to a specific *operation* (e.g. "transfer money") rather than a
route's general request-security posture, and often need an app-supplied
identity (the authenticated user, not just the IP).

Example
-------
>>> @app.post("/transfer")
... @aegis.protect_action(
...     "transfer",
...     quota="10/day",
...     dedupe_header="Idempotency-Key",
...     identity=lambda: current_user.id,
... )
... def transfer():
...     ...
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .exceptions import AegisError
from .ratelimit import RateLimiter


class BusinessRuleViolation(AegisError):
    """Raised when a business rule rejects the current action.

    ``reason`` is one of: 'quota_exceeded', 'duplicate_request'.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass
class _ReplayEntry:
    result_marker: str
    expires_at: float


class ReplayGuard:
    """In-memory idempotency-key tracker: the same key seen twice within
    ``ttl_seconds`` is treated as a duplicate/replayed request rather than
    a new one -- the same protection an ``Idempotency-Key`` header gives
    payment APIs.

    Not shared across processes. For multi-process deployments, back this
    with the same Redis connection used for rate limiting (swap the
    in-memory dict for a Redis SETNX with expiry) -- the interface here
    (`seen`) is intentionally small so that's a drop-in replacement.
    """

    def __init__(self, ttl_seconds: int = 86400):
        self.ttl_seconds = ttl_seconds
        self._seen: dict = {}

    def seen(self, key: str) -> bool:
        """Return True if ``key`` was already recorded and hasn't expired.
        Records ``key`` as seen either way (first call always returns
        False and marks it seen; the point is to call this once per
        request attempt)."""
        now = time.monotonic()
        self._gc(now)
        if key in self._seen:
            return True
        self._seen[key] = _ReplayEntry(result_marker="seen", expires_at=now + self.ttl_seconds)
        return False

    def _gc(self, now: float) -> None:
        expired = [k for k, v in self._seen.items() if v.expires_at <= now]
        for k in expired:
            del self._seen[k]


@dataclass
class ActionPolicy:
    name: str
    quota: Optional[str] = None          # e.g. "10/day" -- same spec format as rate_limit
    dedupe_header: Optional[str] = None  # header name carrying an idempotency key
    identity: Optional[Callable[[], str]] = None
    """Callable returning the current caller's identity for quota scoping
    (e.g. `lambda: current_user.id`). Falls back to remote_addr if unset."""


class BusinessRules:
    """Registry + enforcement point for :class:`ActionPolicy` definitions,
    used by ``Aegis.protect_action``."""

    def __init__(self, rate_limiter: Optional[RateLimiter] = None,
                 replay_guard: Optional[ReplayGuard] = None):
        self.rate_limiter = rate_limiter or RateLimiter()
        self.replay_guard = replay_guard or ReplayGuard()
        self._policies: dict = {}

    def add(self, policy: ActionPolicy) -> None:
        self._policies[policy.name] = policy

    def enforce(self, action_name: str, request) -> None:
        """Run every configured check for ``action_name`` against the
        current request. Raises :class:`BusinessRuleViolation` on the
        first failing check."""
        policy = self._policies.get(action_name)
        if policy is None:
            return

        identity = policy.identity() if policy.identity else (request.remote_addr or "anonymous")

        if policy.dedupe_header:
            key = request.headers.get(policy.dedupe_header)
            if key:
                dedupe_key = f"{action_name}:{identity}:{key}"
                if self.replay_guard.seen(dedupe_key):
                    raise BusinessRuleViolation(
                        "duplicate_request",
                        f"Request with {policy.dedupe_header}={key!r} was already processed",
                    )

        if policy.quota:
            result = self.rate_limiter.check(identity, policy.quota, scope=f"action:{action_name}")
            if not result.allowed:
                raise BusinessRuleViolation(
                    "quota_exceeded",
                    f"Quota exceeded for action '{action_name}' ({policy.quota})",
                )
