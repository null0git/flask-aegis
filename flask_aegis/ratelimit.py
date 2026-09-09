"""
flask_aegis.ratelimit
~~~~~~~~~~~~~~~~~~~~~~~

Sliding-window rate limiting with pluggable storage.

The in-memory backend is the default (zero setup, fine for a single
process / development). :class:`RedisBackend` is provided for multi-process
deployments — install with ``pip install flask-aegis[redis]``.

Custom backends only need to implement :meth:`Backend.hit`.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Optional, Protocol


class Backend(Protocol):
    def hit(self, key: str, limit: int, window_seconds: int) -> "HitResult":
        ...


@dataclass
class HitResult:
    allowed: bool
    remaining: int
    reset_after: float


class MemoryBackend:
    """Thread-safe sliding-window counter kept in process memory.

    Not shared across worker processes — fine for development or a
    single-process deployment; use :class:`RedisBackend` otherwise.
    """

    def __init__(self):
        self._lock = Lock()
        self._buckets: dict[str, deque] = {}

    def hit(self, key: str, limit: int, window_seconds: int) -> HitResult:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            cutoff = now - window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            if len(bucket) >= limit:
                reset_after = window_seconds - (now - bucket[0])
                return HitResult(allowed=False, remaining=0, reset_after=max(reset_after, 0))

            bucket.append(now)
            return HitResult(
                allowed=True,
                remaining=limit - len(bucket),
                reset_after=window_seconds,
            )


class RedisBackend:
    """Sliding-window counter backed by Redis sorted sets, for
    multi-process/multi-node deployments. Requires ``pip install
    flask-aegis[redis]``.
    """

    def __init__(self, client=None, url: Optional[str] = None, prefix: str = "aegis:rl:"):
        if client is None:
            try:
                import redis
            except ImportError as exc:  # pragma: no cover
                raise ImportError(
                    "RedisBackend requires the 'redis' package: "
                    "pip install flask-aegis[redis]"
                ) from exc
            client = redis.Redis.from_url(url or "redis://localhost:6379/0")
        self.client = client
        self.prefix = prefix

    def hit(self, key: str, limit: int, window_seconds: int) -> HitResult:
        now = time.time()
        redis_key = f"{self.prefix}{key}"
        pipe = self.client.pipeline()
        cutoff = now - window_seconds
        pipe.zremrangebyscore(redis_key, 0, cutoff)
        pipe.zcard(redis_key)
        pipe.zadd(redis_key, {str(now): now})
        pipe.expire(redis_key, window_seconds)
        _, count, *_ = pipe.execute()

        if count >= limit:
            self.client.zrem(redis_key, str(now))  # undo the speculative add
            oldest = self.client.zrange(redis_key, 0, 0, withscores=True)
            reset_after = window_seconds
            if oldest:
                reset_after = max(window_seconds - (now - oldest[0][1]), 0)
            return HitResult(allowed=False, remaining=0, reset_after=reset_after)

        return HitResult(allowed=True, remaining=limit - count - 1, reset_after=window_seconds)


_WINDOW_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}


def parse_rate(spec: str) -> tuple[int, int]:
    """Parse ``"5/minute"`` -> (5, 60)."""
    count_s, _, per = spec.partition("/")
    return int(count_s), _WINDOW_SECONDS[per]


class RateLimiter:
    """Evaluates a rate-limit spec against an identity key using the
    configured backend.

    Example
    -------
    >>> limiter = RateLimiter(MemoryBackend())
    >>> limiter.check("192.0.2.1", "5/minute")
    HitResult(allowed=True, remaining=4, reset_after=60)
    """

    def __init__(self, backend: Optional[Backend] = None):
        self.backend = backend or MemoryBackend()

    def check(self, identity: str, spec: str, scope: str = "ip") -> HitResult:
        limit, window = parse_rate(spec)
        key = f"{scope}:{identity}:{spec}"
        return self.backend.hit(key, limit, window)
