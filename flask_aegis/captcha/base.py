"""
flask_aegis.captcha.base
~~~~~~~~~~~~~~~~~~~~~~~~~~

CAPTCHA provider interface. Flask-Aegis is frontend-agnostic: the provider
exposes only a *public* config dict (safe to embed in Jinja, a React
component, or a mobile client) and a server-side ``verify`` method. The
secret key never leaves this module's process boundary.
"""
from __future__ import annotations

from typing import Optional


class CaptchaProvider:
    """Base class every CAPTCHA integration implements.

    Subclasses must not expose ``secret_key`` (or equivalent) through
    :meth:`public_config` — that dict is safe to serialize straight into
    an API response or a Jinja template.
    """

    name: str = "base"

    def public_config(self) -> dict:
        """Return only what a frontend needs to render the widget
        (site key, provider name, theme). Never include secrets here."""
        raise NotImplementedError

    def verify(self, token: str, remote_ip: Optional[str] = None) -> bool:
        """Verify a challenge response server-side. Must be called from
        request handling code only — never expose this over an API that
        a client could call directly with an arbitrary token/ip pair
        unless you also validate the token was issued to this session."""
        raise NotImplementedError

    def render_jinja(self) -> str:
        """Return an HTML snippet for `{{ aegis.captcha() }}` in Jinja
        templates. Frameworks other than Jinja should call
        `public_config()` from an API endpoint instead and render their
        own widget."""
        raise NotImplementedError
