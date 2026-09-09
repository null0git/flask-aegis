import pytest

from flask_aegis.ssrf import SSRFBlocked, SSRFGuard


def test_blocks_link_local_metadata_ip():
    guard = SSRFGuard()
    with pytest.raises(SSRFBlocked):
        guard.validate_url("http://169.254.169.254/latest/meta-data/")


def test_blocks_file_scheme():
    guard = SSRFGuard()
    with pytest.raises(SSRFBlocked):
        guard.validate_url("file:///etc/passwd")


def test_blocks_loopback_with_denied_port():
    guard = SSRFGuard()
    with pytest.raises(SSRFBlocked):
        guard.validate_url("http://127.0.0.1:6379/")


def test_blocks_private_range_by_default():
    guard = SSRFGuard()
    with pytest.raises(SSRFBlocked):
        guard.validate_url("http://10.0.0.5/internal")


def test_allows_private_range_when_explicitly_enabled():
    guard = SSRFGuard(allow_private=True)
    assert guard.validate_url("http://10.0.0.5/internal") == "http://10.0.0.5/internal"


def test_allows_public_https_url():
    guard = SSRFGuard()
    assert guard.validate_url("https://example.com/") == "https://example.com/"


def test_allowlist_rejects_unlisted_host():
    guard = SSRFGuard(allowed_hosts={"api.trusted.com"})
    with pytest.raises(SSRFBlocked):
        guard.validate_url("https://not-trusted.com/")
