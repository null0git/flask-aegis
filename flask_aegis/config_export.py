"""
flask_aegis.config_export
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Builds a plain-dict snapshot of an :class:`~flask_aegis.Aegis` instance's
compiled configuration, suitable for YAML/JSON export via
``flask aegis config export``.

**Never includes secrets.** Only the CAPTCHA provider's *name* is
exported (e.g. ``"recaptcha"``), never its site/secret keys -- see
:func:`export_config`'s docstring for the exact exclusion list. This is
enforced by construction (the function only reads specific known-safe
attributes off each object), not by a denylist filtering a dump of
everything -- so a new field added to a provider later doesn't
accidentally leak through this path.
"""
from __future__ import annotations


def export_config(aegis) -> dict:
    """Returns a plain dict describing ``aegis``'s active configuration:
    profile, mode, ruleset, every compiled policy's resolved settings,
    the security-headers configuration, and which CAPTCHA provider is
    active (by name only).

    Excluded on purpose: CAPTCHA site/secret keys, the rate limiter's
    backend connection details (e.g. a Redis URL, which may embed
    credentials), and anything from Flask's own ``app.config`` (which
    could contain ``SECRET_KEY``, database URLs, or other application
    secrets unrelated to Aegis itself).
    """
    policies = {}
    for name, compiled in aegis._compiled.items():
        if name.startswith("__ratelimit__"):
            continue
        policies[name] = {
            "csrf": compiled.csrf,
            "xss": compiled.xss,
            "sqli": compiled.sqli,
            "traversal": compiled.traversal,
            "ssti": compiled.ssti,
            "cmdi": compiled.cmdi,
            "ldap": compiled.ldap,
            "xpath": compiled.xpath,
            "header_injection": compiled.header_injection,
            "csv_injection": compiled.csv_injection,
            "nosqli": compiled.nosqli,
            "xxe": compiled.xxe,
            "open_redirect": compiled.open_redirect,
            "hpp": compiled.hpp,
            "deserialization": compiled.deserialization,
            "ssrf_field": compiled.ssrf_field,
            "proto_pollution": compiled.proto_pollution,
            "el_injection": compiled.el_injection,
            "mass_assignment": compiled.mass_assignment,
            "redos": compiled.redos,
            "jwt_weak": compiled.jwt_weak,
            "homograph": compiled.homograph,
            "xml_bomb": compiled.xml_bomb,
            "ssi_injection": compiled.ssi_injection,
            "latex_injection": compiled.latex_injection,
            "format_string": compiled.format_string,
            "rate_limit": compiled.rate_limit,
            "captcha": compiled.captcha,
            "risk_threshold": compiled.risk_threshold,
            "max_body_size": compiled.max_body_size,
            "headers": compiled.headers,
        }

    headers_cfg = aegis.security_headers.config
    headers = {
        "csp": headers_cfg.csp if isinstance(headers_cfg.csp, bool) else "custom",
        "hsts": headers_cfg.hsts,
        "hsts_max_age": headers_cfg.hsts_max_age,
        "nosniff": headers_cfg.nosniff,
        "frame_protection": headers_cfg.frame_protection,
        "referrer_policy": headers_cfg.referrer_policy,
        "permissions_policy": headers_cfg.permissions_policy,
        "secure_cookies": headers_cfg.secure_cookies,
    }

    return {
        "flask_aegis_version": _package_version(),
        "profile": aegis.profile_name,
        "mode": aegis.mode,
        "ruleset": aegis.ruleset,
        "captcha_provider": getattr(aegis.captcha_provider, "name", None),
        "rate_limiter_backend": type(aegis.rate_limiter.backend).__name__,
        "security_headers": headers,
        "policies": policies,
        "rule_ids": sorted(r.meta.rule_id for r in aegis.rules.all()),
    }


def _package_version() -> str:
    from . import __version__
    return __version__
