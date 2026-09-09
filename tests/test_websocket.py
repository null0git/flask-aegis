import pytest

from flask_aegis.websocket import WebSocketBlocked, WebSocketGuard


def test_allowed_origin_passes():
    guard = WebSocketGuard(allowed_origins={"https://example.com"})
    assert guard.validate_origin("https://example.com") is True


def test_disallowed_origin_fails():
    guard = WebSocketGuard(allowed_origins={"https://example.com"})
    assert guard.validate_origin("https://evil.com") is False


def test_none_origin_fails_when_allowlist_set():
    guard = WebSocketGuard(allowed_origins={"https://example.com"})
    assert guard.validate_origin(None) is False


def test_no_allowlist_allows_any_origin():
    guard = WebSocketGuard(allowed_origins=None)
    assert guard.validate_origin("https://anything.com") is True


def test_connection_limit_enforced():
    guard = WebSocketGuard(max_concurrent_connections=2)
    guard.connect()
    guard.connect()
    assert guard.active_connection_count == 2
    with pytest.raises(WebSocketBlocked) as exc:
        guard.connect()
    assert exc.value.reason == "connection_limit_exceeded"


def test_disconnect_frees_a_slot():
    guard = WebSocketGuard(max_concurrent_connections=1)
    c1 = guard.connect()
    guard.disconnect(c1)
    assert guard.active_connection_count == 0
    guard.connect()  # should not raise


def test_oversized_message_blocked():
    guard = WebSocketGuard(max_message_size=10)
    with pytest.raises(WebSocketBlocked) as exc:
        guard.check_message("conn1", "this message is way too long")
    assert exc.value.reason == "message_too_large"


def test_small_message_allowed():
    guard = WebSocketGuard(max_message_size=10)
    guard.check_message("conn1", "short")  # should not raise


def test_rate_limit_enforced_per_connection():
    guard = WebSocketGuard(max_messages_per_minute=3)
    for _ in range(3):
        guard.check_message("connA", "msg")
    with pytest.raises(WebSocketBlocked) as exc:
        guard.check_message("connA", "msg")
    assert exc.value.reason == "rate_limit_exceeded"


def test_rate_limit_independent_per_connection():
    guard = WebSocketGuard(max_messages_per_minute=1)
    guard.check_message("connA", "msg")
    guard.check_message("connB", "msg")  # different connection, should not raise
