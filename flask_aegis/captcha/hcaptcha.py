"""
flask_aegis.captcha.hcaptcha
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

hCaptcha provider.

This module exists as much to *demonstrate* the CAPTCHA plugin
architecture as to be useful on its own: it's a second, independent
implementation of :class:`~flask_aegis.captcha.base.CaptchaProvider`
built the same way a third-party plugin would be, registered the same
way (`aegis.register_provider("hcaptcha", HcaptchaProvider)`), proving
the interface is genuinely provider-agnostic rather than shaped around
reCAPTCHA specifically.

Security note
-------------
Same discipline as ``recaptcha.py``: ``secret_key`` is used only inside
:meth:`verify`, which makes a server-to-server POST to hCaptcha's API.
It is never placed in ``public_config()``, never rendered into a
template, and never returned from a Flask-Aegis API endpoint.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from ..exceptions import CaptchaError
from .base import CaptchaProvider

_VERIFY_URL = "https://hcaptcha.com/siteverify"


class HcaptchaProvider(CaptchaProvider):
    name = "hcaptcha"

    def __init__(self, site_key: str, secret_key: str, timeout: float = 5.0):
        if not site_key or not secret_key:
            raise CaptchaError("HcaptchaProvider requires both site_key and secret_key")
        self.site_key = site_key
        self._secret_key = secret_key  # underscore: signal "do not export"
        self.timeout = timeout

    def public_config(self) -> dict:
        # Deliberately excludes self._secret_key.
        return {"provider": self.name, "site_key": self.site_key}

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
                result = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError) as exc:
            raise CaptchaError(f"hCaptcha verification request failed: {exc}") from exc

        return bool(result.get("success"))

    def render_jinja(self) -> str:
        return (
            f'<div class="h-captcha" data-sitekey="{self.site_key}"></div>\n'
            '<script src="https://js.hcaptcha.com/1/api.js" async defer></script>'
        )
