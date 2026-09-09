"""
flask_aegis.captcha.recaptcha
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Google reCAPTCHA v2/v3 provider.

Security note
-------------
``secret_key`` is used only inside :meth:`verify`, which makes a
server-to-server POST to Google. It is never placed in ``public_config()``,
never rendered into a template, and never returned from a Flask-Aegis API
endpoint. If you are extending this provider, keep it that way -- see
SECURITY.md's guidance on secret handling.
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from ..exceptions import CaptchaError
from .base import CaptchaProvider

_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


class RecaptchaProvider(CaptchaProvider):
    name = "recaptcha"

    def __init__(
        self,
        site_key: str,
        secret_key: str,
        version: str = "v2",
        score_threshold: float = 0.5,
        timeout: float = 5.0,
    ):
        if not site_key or not secret_key:
            raise CaptchaError("RecaptchaProvider requires both site_key and secret_key")
        self.site_key = site_key
        self._secret_key = secret_key  # underscore: signal "do not export"
        self.version = version
        self.score_threshold = score_threshold
        self.timeout = timeout

    def public_config(self) -> dict:
        # Deliberately excludes self._secret_key.
        return {
            "provider": self.name,
            "site_key": self.site_key,
            "version": self.version,
        }

    def verify(self, token: str, remote_ip: Optional[str] = None) -> bool:
        if not token:
            return False

        payload = {"secret": self._secret_key, "response": token}
        if remote_ip:
            payload["remoteip"] = remote_ip

        data = urllib.parse.urlencode(payload).encode()
        req = urllib.request.Request(_VERIFY_URL, data=data, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                import json
                result = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError) as exc:
            raise CaptchaError(f"reCAPTCHA verification request failed: {exc}") from exc

        if not result.get("success"):
            return False
        if self.version == "v3":
            return float(result.get("score", 0.0)) >= self.score_threshold
        return True

    def render_jinja(self) -> str:
        return (
            f'<div class="g-recaptcha" data-sitekey="{self.site_key}"></div>\n'
            '<script src="https://www.google.com/recaptcha/api.js" async defer></script>'
        )


class NullProvider(CaptchaProvider):
    """No-op provider used when captcha is configured but no real provider
    is set up yet (e.g. local development). Always fails verification so
    it can never be mistaken for a working challenge in production."""

    name = "null"

    def public_config(self) -> dict:
        return {"provider": "null"}

    def verify(self, token: str, remote_ip: Optional[str] = None) -> bool:
        return False

    def render_jinja(self) -> str:
        return "<!-- flask-aegis: no CAPTCHA provider configured -->"
