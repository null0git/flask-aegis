"""
flask_aegis.headers
~~~~~~~~~~~~~~~~~~~~~

Response-side security hardening: headers, cookie flags, and cache-control
policy. Applied via an ``after_request`` hook so it runs regardless of
which view produced the response — including error handlers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HeaderConfig:
    csp: object = True
    """True for a sane default CSP, False to disable, or a str for a
    custom policy value."""

    hsts: bool = True
    hsts_max_age: int = 31536000  # 1 year
    nosniff: bool = True
    frame_protection: str = "DENY"  # DENY | SAMEORIGIN | off
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: Optional[str] = None
    secure_cookies: bool = True

    extra: dict = field(default_factory=dict)
    """Arbitrary extra headers to always add, e.g.
    {"X-Custom-Security": "value"}."""

    def default_csp(self) -> str:
        return (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )


class SecurityHeaders:
    """Applies :class:`HeaderConfig` to every outgoing response.

    Example
    -------
    >>> aegis.headers(csp=True, hsts=True, nosniff=True,
    ...                frame_protection="SAMEORIGIN",
    ...                referrer_policy="no-referrer")
    """

    def __init__(self, config: Optional[HeaderConfig] = None):
        self.config = config or HeaderConfig()

    def configure(self, **overrides) -> None:
        for key, value in overrides.items():
            if not hasattr(self.config, key):
                raise ValueError(f"Unknown header option: {key!r}")
            setattr(self.config, key, value)

    def apply(self, response):
        cfg = self.config

        if cfg.csp:
            response.headers.setdefault(
                "Content-Security-Policy",
                cfg.csp if isinstance(cfg.csp, str) else cfg.default_csp(),
            )
        if cfg.hsts:
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={cfg.hsts_max_age}; includeSubDomains",
            )
        if cfg.nosniff:
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
        if cfg.frame_protection and cfg.frame_protection != "off":
            response.headers.setdefault(
                "X-Frame-Options", cfg.frame_protection
            )
        if cfg.referrer_policy:
            response.headers.setdefault("Referrer-Policy", cfg.referrer_policy)
        if cfg.permissions_policy:
            response.headers.setdefault(
                "Permissions-Policy", cfg.permissions_policy
            )
        for name, value in cfg.extra.items():
            response.headers.setdefault(name, value)

        if cfg.secure_cookies:
            self._harden_cookies(response)

        return response

    @staticmethod
    def _harden_cookies(response) -> None:
        """Ensure every Set-Cookie header on this response carries
        Secure, HttpOnly, and SameSite unless the application explicitly
        set them otherwise."""
        cookies = response.headers.getlist("Set-Cookie")
        if not cookies:
            return
        response.headers.remove("Set-Cookie")
        for cookie in cookies:
            lowered = cookie.lower()
            if "secure" not in lowered:
                cookie += "; Secure"
            if "httponly" not in lowered:
                cookie += "; HttpOnly"
            if "samesite" not in lowered:
                cookie += "; SameSite=Lax"
            response.headers.add("Set-Cookie", cookie)
