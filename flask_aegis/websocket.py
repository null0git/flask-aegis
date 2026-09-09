"""
flask_aegis.websocket
~~~~~~~~~~~~~~~~~~~~~~~

WebSocket-specific abuse protection: origin validation, per-connection
message-rate limiting, message-size limits, and connection-count caps.

Flask has no built-in WebSocket support, and this module deliberately
adds no new dependency on a specific WebSocket library (Flask-Sock,
Flask-SocketIO, etc.) -- the primitives here (``WebSocketGuard``) are a
plain Python class you call from inside whichever WS library's
connection/message handler you're already using.

Example (Flask-Sock)
---------------------
>>> from flask_sock import Sock
>>> from flask_aegis.websocket import WebSocketGuard, WebSocketBlocked
>>>
>>> sock = Sock(app)
>>> guard = WebSocketGuard(
...     allowed_origins={"https://example.com"},
...     max_message_size=64 * 1024,
...     max_messages_per_minute=120,
... )
>>>
>>> @sock.route("/ws")
... def ws_handler(ws):
...     if not guard.validate_origin(request.headers.get("Origin")):
...         return  # reject the connection
...     connection_id = guard.connect()
...     try:
...         while True:
...             message = ws.receive()
...             if message is None:
...                 break
...             try:
...                 guard.check_message(connection_id, message)
...             except WebSocketBlocked as exc:
...                 ws.send(str(exc))
...                 break
...             handle_message(message)
...     finally:
...         guard.disconnect(connection_id)
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .exceptions import AegisError
from .ratelimit import MemoryBackend, RateLimiter


class WebSocketBlocked(AegisError):
    """Raised when a WebSocket connection or message violates a
    configured limit. ``reason`` is one of: 'origin_not_allowed',
    'message_too_large', 'rate_limit_exceeded', 'connection_limit_exceeded'."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


@dataclass
class WebSocketGuard:
    """Connection- and message-level limits for a WebSocket endpoint.
    Library-agnostic: call its methods from inside your WS handler.

    ``allowed_origins`` of ``None`` disables origin checking entirely
    (not recommended for a browser-facing endpoint -- WebSocket
    connections are not subject to the same-origin policy the way
    fetch()/XHR are, so an attacker's page can open a WS connection to
    your endpoint from any origin unless you check it yourself)."""

    allowed_origins: Optional[set] = None
    max_message_size: int = 128 * 1024
    max_messages_per_minute: int = 120
    max_concurrent_connections: Optional[int] = None
    """Global cap across all connections tracked by this guard instance.
    None disables the cap."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _active_connections: set = field(default_factory=set, repr=False)
    _rate_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(MemoryBackend()), repr=False)

    def validate_origin(self, origin: Optional[str]) -> bool:
        """Returns True if ``origin`` is allowed to open a connection.
        Call this before accepting/upgrading the connection, not after."""
        if self.allowed_origins is None:
            return True
        return origin in self.allowed_origins

    def connect(self) -> str:
        """Register a new connection and return its id. Raises
        :class:`WebSocketBlocked` if ``max_concurrent_connections`` is
        set and already at capacity."""
        with self._lock:
            if (self.max_concurrent_connections is not None
                    and len(self._active_connections) >= self.max_concurrent_connections):
                raise WebSocketBlocked(
                    "connection_limit_exceeded",
                    f"Maximum concurrent connections ({self.max_concurrent_connections}) reached",
                )
            connection_id = str(uuid.uuid4())
            self._active_connections.add(connection_id)
            return connection_id

    def disconnect(self, connection_id: str) -> None:
        """Release a connection's slot. Always call this when a
        connection closes, in a ``finally`` block, so an abruptly
        dropped connection doesn't permanently consume capacity."""
        with self._lock:
            self._active_connections.discard(connection_id)

    def check_message(self, connection_id: str, message) -> None:
        """Validate one incoming message against the size and
        per-connection rate limits. Raises :class:`WebSocketBlocked` on
        the first violated limit; callers typically close the
        connection (or send an error frame then close) in response,
        since a client already violating a message-level limit is not
        one you generally want to keep talking to.
        """
        size = len(message) if isinstance(message, (str, bytes)) else len(str(message))
        if size > self.max_message_size:
            raise WebSocketBlocked(
                "message_too_large",
                f"Message size {size} bytes exceeds the limit of {self.max_message_size} bytes",
            )

        result = self._rate_limiter.check(
            connection_id, f"{self.max_messages_per_minute}/minute", scope="ws_connection"
        )
        if not result.allowed:
            raise WebSocketBlocked(
                "rate_limit_exceeded",
                f"Exceeded {self.max_messages_per_minute} messages/minute on this connection",
            )

    @property
    def active_connection_count(self) -> int:
        with self._lock:
            return len(self._active_connections)
