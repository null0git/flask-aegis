"""
flask_aegis.ssrf
~~~~~~~~~~~~~~~~~~

SSRF defense is deliberately **not** implemented as a request-body payload
scanner — a URL that "looks like" SSRF in a form field is not the actual
vulnerability. The actual vulnerability is *your application code making
an outbound HTTP request to a URL influenced by user input*. So instead of
scanning, Flask-Aegis provides a validator you call at the point your code
is about to make that outbound request (a webhook callback, an
image-fetch-by-URL feature, an "import from URL" endpoint, ...).

Example
-------
>>> from flask_aegis.ssrf import SSRFGuard
>>> guard = SSRFGuard()
>>> guard.validate_url("http://169.254.169.254/latest/meta-data/")
Traceback (most recent call last):
    ...
flask_aegis.exceptions.AegisError: URL resolves to a blocked address range: link-local (169.254.169.254)

>>> guard.validate_url("https://api.example.com/webhook")  # OK, does nothing
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from .exceptions import AegisError


class SSRFBlocked(AegisError):
    """Raised by :meth:`SSRFGuard.validate_url` when a URL resolves to a
    disallowed address or uses a disallowed scheme."""


@dataclass
class SSRFGuard:
    """Validates that a URL is safe to fetch from server-side code.

    By default, blocks:

    * Non-HTTP(S) schemes (``file://``, ``gopher://``, ``dict://``, ...)
    * Loopback (``127.0.0.0/8``, ``::1``)
    * Link-local, including the common cloud metadata address
      ``169.254.169.254``
    * Private ranges (RFC1918: ``10.0.0.0/8``, ``172.16.0.0/12``,
      ``192.168.0.0/16``) and their IPv6 equivalents
    * Multicast and reserved ranges

    Set ``allow_private=True`` to permit internal service-to-service
    calls in a deployment where that's an intentional, trusted pattern —
    but prefer an explicit allowlist (``allowed_hosts``) over disabling
    this wholesale.
    """

    allowed_schemes: tuple = ("http", "https")
    allow_private: bool = False
    allow_loopback: bool = False
    allowed_hosts: Optional[set] = None
    """If set, only these exact hostnames are permitted (checked before
    DNS resolution) — the strongest possible defense when the set of
    legitimate destinations is known (e.g. a fixed list of webhook
    partners)."""

    denied_ports: set = field(default_factory=lambda: {25, 587, 465, 6379, 11211, 9200, 2375})
    """Ports commonly associated with internal services (SMTP, Redis,
    Memcached, Elasticsearch, unauthenticated Docker) — blocked even on an
    otherwise-permitted host, since exposing them is a classic SSRF
    escalation."""

    def validate_url(self, url: str) -> str:
        """Return ``url`` unchanged if it passes validation, otherwise
        raise :class:`SSRFBlocked`. Call this immediately before making
        the outbound request — not earlier, and not on a cached/stored
        copy, since DNS can change between validation and use (DNS
        rebinding); for high-value targets, resolve once and connect to
        the resolved IP directly rather than re-resolving in your HTTP
        client.
        """
        parsed = urlparse(url)

        if parsed.scheme not in self.allowed_schemes:
            raise SSRFBlocked(
                f"URL scheme {parsed.scheme!r} is not allowed "
                f"(allowed: {', '.join(self.allowed_schemes)})"
            )

        if not parsed.hostname:
            raise SSRFBlocked("URL has no hostname")

        if self.allowed_hosts is not None and parsed.hostname not in self.allowed_hosts:
            raise SSRFBlocked(
                f"Host {parsed.hostname!r} is not in the configured allowlist"
            )

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port in self.denied_ports:
            raise SSRFBlocked(f"Port {port} is not allowed for outbound requests")

        self._validate_address(parsed.hostname)
        return url

    def _validate_address(self, hostname: str) -> None:
        try:
            ip = ipaddress.ip_address(hostname)
            self._check_ip(ip, hostname)
            return
        except ValueError:
            pass  # not a literal IP -- resolve it

        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise SSRFBlocked(f"Could not resolve host {hostname!r}: {exc}") from exc

        for info in infos:
            addr = info[4][0]
            ip = ipaddress.ip_address(addr)
            self._check_ip(ip, hostname)

    def _check_ip(self, ip, hostname: str) -> None:
        if ip.is_loopback and not self.allow_loopback:
            raise SSRFBlocked(f"URL resolves to a loopback address: {hostname} ({ip})")
        if ip.is_link_local:
            raise SSRFBlocked(f"URL resolves to a blocked address range: link-local ({ip})")
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise SSRFBlocked(f"URL resolves to a blocked address range: reserved ({ip})")
        if ip.is_private and not self.allow_private:
            raise SSRFBlocked(f"URL resolves to a private address: {hostname} ({ip})")
