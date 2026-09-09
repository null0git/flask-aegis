from flask_aegis.ratelimit import MemoryBackend, RateLimiter, parse_rate


def test_parse_rate():
    assert parse_rate("5/minute") == (5, 60)
    assert parse_rate("1/second") == (1, 1)
    assert parse_rate("100/hour") == (100, 3600)


def test_limiter_allows_up_to_limit():
    limiter = RateLimiter(MemoryBackend())
    for _ in range(5):
        result = limiter.check("1.2.3.4", "5/minute")
        assert result.allowed
    result = limiter.check("1.2.3.4", "5/minute")
    assert not result.allowed


def test_limiter_scopes_are_independent():
    limiter = RateLimiter(MemoryBackend())
    for _ in range(5):
        assert limiter.check("1.2.3.4", "5/minute").allowed
    # Different identity, same spec -> fresh bucket.
    assert limiter.check("5.6.7.8", "5/minute").allowed
