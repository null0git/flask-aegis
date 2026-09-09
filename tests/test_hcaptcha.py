import pytest

from flask_aegis.captcha import HcaptchaProvider, build_provider
from flask_aegis.exceptions import CaptchaError


def test_public_config_excludes_secret():
    p = HcaptchaProvider(site_key="site123", secret_key="secret456")
    assert "secret456" not in str(p.public_config())


def test_public_config_includes_site_key():
    p = HcaptchaProvider(site_key="site123", secret_key="secret456")
    assert p.public_config() == {"provider": "hcaptcha", "site_key": "site123"}


def test_render_jinja_includes_site_key_excludes_secret():
    p = HcaptchaProvider(site_key="site123", secret_key="secret456")
    rendered = p.render_jinja()
    assert "site123" in rendered
    assert "secret456" not in rendered


def test_empty_token_fails_verify_without_network_call():
    p = HcaptchaProvider(site_key="site123", secret_key="secret456")
    assert p.verify("") is False


def test_missing_site_key_raises():
    with pytest.raises(CaptchaError):
        HcaptchaProvider(site_key="", secret_key="x")


def test_missing_secret_key_raises():
    with pytest.raises(CaptchaError):
        HcaptchaProvider(site_key="x", secret_key="")


def test_build_provider_resolves_hcaptcha():
    p = build_provider({"provider": "hcaptcha", "site_key": "a", "secret_key": "b"})
    assert isinstance(p, HcaptchaProvider)
    assert p.name == "hcaptcha"
