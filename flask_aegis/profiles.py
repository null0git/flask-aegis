"""
flask_aegis.profiles
~~~~~~~~~~~~~~~~~~~~~~

Built-in security profiles. A profile is just a set of default values fed
into the :class:`~flask_aegis.policy.PolicyEngine` — it is the "reasonable
defaults" layer, not a separate mechanism. Policies (see policy.py) can
still override anything a profile sets.

Run ``flask aegis profile show <name>`` to print exactly what a profile
enables, in plain language, before relying on it.

Notes on narrow-surface / opt-in categories:

- ``ldap``/``xpath``: LDAP-backed directories and XML/XPath search
  endpoints are a narrow surface. Most profiles leave these off; enable
  explicitly with ``aegis.add_policy(..., ldap=True)`` on routes that
  actually touch those sinks.
- ``csv_injection``/``open_redirect``/``ssrf_field``/``redos``/
  ``homograph``/``ssi_injection``/``latex_injection``/``format_string``:
  these use a **double opt-in** by design. Even where a profile enables
  the category, the underlying rule's own per-field default is OFF --
  you must also call ``aegis.field(route, field_name, redos=True)``
  (etc.) on the specific field that actually needs the check. This
  prevents these rules from firing on every ordinary field just because
  the category is nominally "on" for the route. Enabling the category
  broadly is therefore harmless -- it costs nothing until a field opts in.
- ``nosqli``/``xxe``/``xml_bomb``/``hpp``/``deserialization``/
  ``proto_pollution``/``el_injection``/``mass_assignment``/``jwt_weak``:
  these default to firing on every field once their category is
  enabled (like ``sqli``/``traversal``), since a single category-level
  toggle is enough to opt a route in.
"""
from __future__ import annotations

# Shared base for every profile's new (Phase 4) category fields, so each
# profile only overrides what genuinely differs from "on for broadly-
# useful checks, off for narrow-surface ones" -- reduces the risk of
# another profile ending up silently missing a field.
_PHASE4_DEFAULTS = dict(
    nosqli=True, xxe=True, open_redirect=False, hpp=True,
    deserialization=True, ssrf_field=False, proto_pollution=True,
    el_injection=True, mass_assignment=True, redos=False, jwt_weak=True,
    homograph=False, xml_bomb=True, ssi_injection=False,
    latex_injection=False, format_string=False,
)


def _profile(overrides: dict) -> dict:
    merged = dict(_PHASE4_DEFAULTS)
    merged.update(overrides)
    return merged


PROFILES = {
    "minimal": dict(
        csrf=False, xss=False, sqli=False, traversal=False,
        ssti=False, cmdi=False, ldap=False, xpath=False,
        header_injection=False, csv_injection=False,
        **_profile({
            "nosqli": False, "xxe": False, "hpp": False, "deserialization": False,
            "proto_pollution": False, "el_injection": False,
            "mass_assignment": False, "jwt_weak": False, "xml_bomb": False,
        }),
        rate_limit=None, captcha=None, risk_threshold=80, headers=True,
        max_body_size=None,
        description="Security headers only. No request inspection, no "
                    "rate limiting. Use for internal tools or as a base "
                    "you build your own policies on top of.",
    ),
    "standard": dict(
        csrf=True, xss=True, sqli=True, traversal=True,
        ssti=True, cmdi=True, ldap=False, xpath=False,
        header_injection=True, csv_injection=False,
        **_profile({}),
        rate_limit="100/minute", captcha=None, risk_threshold=60,
        headers=True, max_body_size=5 * 1024 * 1024,
        description="Recommended default for typical server-rendered "
                    "applications: CSRF protection, broad injection "
                    "detection across 20+ categories (XSS/SQLi/NoSQLi/"
                    "traversal/SSTI/command/header/XXE/HPP/deserialization/"
                    "prototype pollution/EL injection/mass assignment/JWT/"
                    "XML bomb), a generous global rate limit, and hardened "
                    "response headers.",
    ),
    "strict": dict(
        csrf=True, xss=True, sqli=True, traversal=True,
        ssti=True, cmdi=True, ldap=True, xpath=True,
        header_injection=True, csv_injection=False,
        **_profile({
            "open_redirect": True, "ssrf_field": True, "redos": True,
            "homograph": True, "ssi_injection": True,
            "latex_injection": True, "format_string": True,
        }),
        rate_limit="30/minute", captcha="adaptive", risk_threshold=40,
        headers=True, max_body_size=1 * 1024 * 1024,
        description="Lower thresholds and tighter limits across the board, "
                    "every injection category enabled -- including every "
                    "double-opt-in category's route-level toggle (each "
                    "still needs its own explicit per-field opt-in -- see "
                    "module notes) -- plus adaptive CAPTCHA on risky "
                    "requests. Expect more false positives in exchange "
                    "for stronger defaults.",
    ),
    "api": dict(
        csrf=False, xss=False, sqli=True, traversal=True,
        ssti=True, cmdi=True, ldap=False, xpath=False,
        header_injection=True, csv_injection=False,
        **_profile({}),
        rate_limit="60/minute", captcha=None, risk_threshold=60,
        headers=True, max_body_size=2 * 1024 * 1024,
        description="CSRF disabled (APIs typically use token auth, not "
                    "cookies), but injection and traversal checks remain "
                    "on, including NoSQLi, XXE, deserialization, and JWT "
                    "weak-algorithm detection which are common in JSON "
                    "API bodies and Authorization headers. Pair with "
                    "aegis's OpenAPI/schema validation for full coverage.",
    ),
    "public_form": dict(
        csrf=True, xss=True, sqli=True, traversal=False,
        ssti=True, cmdi=True, ldap=False, xpath=False,
        header_injection=True, csv_injection=False,
        **_profile({"nosqli": False, "xxe": False, "jwt_weak": False}),
        rate_limit="20/minute", captcha="adaptive", risk_threshold=50,
        headers=True, max_body_size=1 * 1024 * 1024,
        description="For public-facing forms (contact, signup, feedback) "
                    "that are common abuse and spam targets.",
    ),
    "authentication": dict(
        csrf=True, xss=True, sqli=True, traversal=False,
        ssti=False, cmdi=False, ldap=True, xpath=False,
        header_injection=True, csv_injection=False,
        **_profile({
            "xxe": False, "proto_pollution": False, "el_injection": False,
            "open_redirect": True, "ssrf_field": True, "homograph": True,
        }),
        rate_limit="5/minute", captcha="adaptive", risk_threshold=40,
        headers=True, max_body_size=64 * 1024,
        description="Tight rate limiting and adaptive CAPTCHA for "
                    "login/password-reset endpoints, tuned to slow down "
                    "credential stuffing and brute force without "
                    "CAPTCHA-walling every legitimate login attempt. LDAP, "
                    "NoSQLi, and JWT weak-algorithm checking are on by "
                    "default since login endpoints commonly sit in front "
                    "of a directory/document database and issue/verify "
                    "tokens; open_redirect's, ssrf_field's, and "
                    "homograph's categories are on since post-login "
                    "redirect targets and SSO/callback URLs are classic "
                    "targets -- remember to opt the specific field in "
                    "with aegis.field(...).",
    ),
    "file_upload": dict(
        csrf=True, xss=False, sqli=False, traversal=True,
        ssti=False, cmdi=False, ldap=False, xpath=False,
        header_injection=True, csv_injection=False,
        **_profile({
            "nosqli": False, "proto_pollution": False, "el_injection": False,
            "mass_assignment": False, "jwt_weak": False,
        }),
        rate_limit="10/minute", captcha=None, risk_threshold=60,
        headers=True, max_body_size=25 * 1024 * 1024,
        description="Traversal and archive-extraction defenses enabled, "
                    "XXE and XML-bomb checking on for XML document "
                    "uploads, deserialization checking on for uploaded "
                    "data files that might contain a serialized-object "
                    "payload, larger body size limit appropriate for "
                    "file bodies. Combine with `aegis.upload(route, ...)` "
                    "for extension allowlisting, double-extension, and "
                    "Zip-Slip protection (see flask_aegis.upload).",
    ),
    "admin": dict(
        csrf=True, xss=True, sqli=True, traversal=True,
        ssti=True, cmdi=True, ldap=True, xpath=True,
        header_injection=True, csv_injection=False,
        **_profile({
            "open_redirect": True, "ssrf_field": True,
        }),
        rate_limit="30/minute", captcha=None, risk_threshold=50,
        headers=True, max_body_size=5 * 1024 * 1024,
        description="Full input-validation coverage for internal admin "
                    "panels, including LDAP/XPath since admin tooling "
                    "commonly fronts a directory service or XML store, "
                    "and mass-assignment detection since admin panels are "
                    "exactly where a naive bulk-update endpoint tends to "
                    "live. No CAPTCHA by default since these routes are "
                    "usually behind authentication already.",
    ),
    "high_security": dict(
        csrf=True, xss=True, sqli=True, traversal=True,
        ssti=True, cmdi=True, ldap=True, xpath=True,
        header_injection=True, csv_injection=False,
        **_profile({
            "open_redirect": True, "ssrf_field": True, "redos": True,
            "homograph": True, "ssi_injection": True,
            "latex_injection": True, "format_string": True,
        }),
        rate_limit="10/minute", captcha="always", risk_threshold=30,
        headers=True, max_body_size=512 * 1024,
        description="Maximum enforcement: every injection category "
                    "enabled, every request faces CAPTCHA, aggressive "
                    "rate limits, and the lowest risk threshold. Expect "
                    "the highest false-positive rate of any built-in "
                    "profile — reserve for the highest-value targets "
                    "(password reset, payment endpoints).",
    ),
}


def get_profile(name: str) -> dict:
    from .exceptions import ConfigurationError

    if name not in PROFILES:
        raise ConfigurationError(
            f"Unknown profile {name!r}. Available profiles: "
            f"{', '.join(sorted(PROFILES))}"
        )
    # Return defaults only (strip the human-readable description before
    # feeding into the PolicyEngine).
    profile = dict(PROFILES[name])
    profile.pop("description", None)
    return profile
