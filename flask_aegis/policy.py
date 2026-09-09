"""
flask_aegis.policy
~~~~~~~~~~~~~~~~~~~~

The policy engine is the central component of Flask-Aegis. A *policy* is a
named bundle of security settings (CSRF, rate limiting, CAPTCHA, risk
threshold, ...) that can be attached to a route with ``@aegis.protect(name)``.

Policies support:

* **Inheritance** - a policy can extend another and override only what
  differs.
* **Priority** - when a route matches more than one applicable policy
  (e.g. a blueprint-level policy and a route-level policy), the highest
  priority wins.
* **Conditions** - a policy can declare a predicate (e.g. "only when
  request.method == 'POST'") that must hold for it to apply.
* **Feature dependencies** - e.g. ``captcha="adaptive"`` implicitly
  requires the risk engine to be enabled.

Resolution happens once, at application startup, and produces a
:class:`CompiledPolicy` per route. Nothing here does dict-merging on the
hot request path — that is the whole point of "compiled policies"
(see the Fast Path section of the README).
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Callable, Optional

from .exceptions import ConfigurationError, PolicyConflictError, PolicyNotFoundError

# Sentinel so we can tell "explicitly set to None/False" apart from
# "not set, inherit from parent".
_UNSET = object()


@dataclass
class Policy:
    """A named, possibly-inheriting bundle of security settings.

    Only fields the caller actually passes are considered "set" — everything
    else is inherited from ``extends`` (if any) or from the active profile's
    defaults at resolution time. This is what lets ``aegis.add_policy(
    "registration", captcha="adaptive")`` override a single field of the
    "public_form" profile without having to restate everything else.
    """

    name: str
    extends: Optional[str] = None
    priority: int = 0
    condition: Optional[Callable[..., bool]] = None

    csrf: object = _UNSET
    xss: object = _UNSET
    sqli: object = _UNSET
    traversal: object = _UNSET
    ssti: object = _UNSET
    cmdi: object = _UNSET
    ldap: object = _UNSET
    xpath: object = _UNSET
    header_injection: object = _UNSET
    csv_injection: object = _UNSET
    nosqli: object = _UNSET
    xxe: object = _UNSET
    open_redirect: object = _UNSET
    hpp: object = _UNSET
    deserialization: object = _UNSET
    ssrf_field: object = _UNSET
    proto_pollution: object = _UNSET
    el_injection: object = _UNSET
    mass_assignment: object = _UNSET
    redos: object = _UNSET
    jwt_weak: object = _UNSET
    homograph: object = _UNSET
    xml_bomb: object = _UNSET
    ssi_injection: object = _UNSET
    latex_injection: object = _UNSET
    format_string: object = _UNSET
    rate_limit: object = _UNSET
    captcha: object = _UNSET
    risk_threshold: object = _UNSET
    max_body_size: object = _UNSET
    headers: object = _UNSET

    actions: dict = field(default_factory=dict)
    """Custom action overrides, e.g. {"on_block": my_handler}."""

    extra: dict = field(default_factory=dict)
    """Arbitrary additional settings for third-party rules/plugins."""

    def field_set(self) -> dict:
        """Return only the fields the user actually specified (not _UNSET)."""
        out = {}
        for f in (
            "csrf", "xss", "sqli", "traversal", "ssti", "cmdi", "ldap",
            "xpath", "header_injection", "csv_injection", "nosqli", "xxe",
            "open_redirect", "hpp", "deserialization", "ssrf_field",
            "proto_pollution", "el_injection", "mass_assignment", "redos",
            "jwt_weak", "homograph", "xml_bomb", "ssi_injection",
            "latex_injection", "format_string", "rate_limit",
            "captcha", "risk_threshold", "max_body_size", "headers",
        ):
            v = getattr(self, f)
            if v is not _UNSET:
                out[f] = v
        return out


# Rule-category fields that map 1:1 onto a RuleRegistry category name.
# Shared by CompiledPolicy.is_noop and the request pipeline's category loop
# so adding a new detection category only means adding it here once.
RULE_CATEGORY_FIELDS = (
    "xss", "sqli", "traversal", "ssti", "cmdi", "ldap", "xpath",
    "header_injection", "csv_injection", "nosqli", "xxe", "open_redirect", "hpp",
    "deserialization", "ssrf_field", "proto_pollution", "el_injection",
    "mass_assignment", "redos", "jwt_weak", "homograph", "xml_bomb",
    "ssi_injection", "latex_injection", "format_string",
)


@dataclass(frozen=True)
class CompiledPolicy:
    """The fully-resolved, immutable result of merging a policy with its
    ancestors and the active profile's defaults. This is what actually gets
    attached to a route and consulted on every request — cheap to read,
    never mutated, never re-resolved."""

    name: str
    csrf: bool = False
    xss: bool = False
    sqli: bool = False
    traversal: bool = False
    ssti: bool = False
    cmdi: bool = False
    ldap: bool = False
    xpath: bool = False
    header_injection: bool = False
    csv_injection: bool = False
    nosqli: bool = False
    xxe: bool = False
    open_redirect: bool = False
    hpp: bool = False
    deserialization: bool = False
    ssrf_field: bool = False
    proto_pollution: bool = False
    el_injection: bool = False
    mass_assignment: bool = False
    redos: bool = False
    jwt_weak: bool = False
    homograph: bool = False
    xml_bomb: bool = False
    ssi_injection: bool = False
    latex_injection: bool = False
    format_string: bool = False
    rate_limit: Optional[str] = None
    captcha: Optional[str] = None  # None | "always" | "adaptive"
    risk_threshold: int = 60
    max_body_size: Optional[int] = None
    headers: bool = True
    condition: Optional[Callable[..., bool]] = None
    actions: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    @property
    def is_noop(self) -> bool:
        """True when this policy enables nothing at all — used by the
        request pipeline to take the fast path and skip the security
        engine entirely."""
        return not (
            any(getattr(self, f) for f in RULE_CATEGORY_FIELDS)
            or self.rate_limit or self.captcha
        )


# Baseline defaults applied when nothing else specifies a value. Individual
# profiles (see profiles.py) override subsets of these.
_BASE_DEFAULTS = dict(
    csrf=False, xss=False, sqli=False, traversal=False,
    ssti=False, cmdi=False, ldap=False, xpath=False,
    header_injection=False, csv_injection=False,
    nosqli=False, xxe=False, open_redirect=False, hpp=False,
    deserialization=False, ssrf_field=False, proto_pollution=False,
    el_injection=False, mass_assignment=False, redos=False, jwt_weak=False,
    homograph=False, xml_bomb=False, ssi_injection=False,
    latex_injection=False, format_string=False,
    rate_limit=None, captcha=None, risk_threshold=60,
    max_body_size=None, headers=True,
)


class PolicyEngine:
    """Registers policies, resolves inheritance, and compiles them.

    Example
    -------
    >>> engine = PolicyEngine(profile_defaults=_BASE_DEFAULTS)
    >>> engine.add(Policy("public_form", csrf=True, xss=True, rate_limit="20/minute"))
    >>> engine.add(Policy("registration", extends="public_form",
    ...                    captcha="adaptive", risk_threshold=60))
    >>> compiled = engine.compile("registration")
    >>> compiled.csrf, compiled.captcha
    (True, 'adaptive')
    """

    def __init__(self, profile_defaults: Optional[dict] = None):
        self._policies: dict[str, Policy] = {}
        self._compiled_cache: dict[str, CompiledPolicy] = {}
        self.profile_defaults = {**_BASE_DEFAULTS, **(profile_defaults or {})}

    def add(self, policy: Policy) -> None:
        if policy.extends and policy.extends == policy.name:
            raise PolicyConflictError(f"Policy {policy.name!r} cannot extend itself")
        self._policies[policy.name] = policy
        self._compiled_cache.clear()  # invalidate — cheap, only happens at setup

    def get(self, name: str) -> Policy:
        try:
            return self._policies[name]
        except KeyError:
            raise PolicyNotFoundError(f"No policy registered with name {name!r}") from None

    def compile(self, name: str) -> CompiledPolicy:
        """Resolve ``name`` against its ancestor chain and profile defaults,
        returning an immutable :class:`CompiledPolicy`. Results are cached —
        call :meth:`compile_all` at startup so requests never pay this cost."""
        if name in self._compiled_cache:
            return self._compiled_cache[name]

        chain = self._ancestor_chain(name)
        merged = dict(self.profile_defaults)
        actions: dict = {}
        extra: dict = {}
        condition = None
        for policy in chain:  # root-most first, most specific last
            merged.update(policy.field_set())
            actions.update(policy.actions)
            extra.update(policy.extra)
            if policy.condition is not None:
                condition = policy.condition

        compiled = CompiledPolicy(
            name=name,
            condition=condition,
            actions=actions,
            extra=extra,
            **merged,
        )
        self._validate(compiled)
        self._compiled_cache[name] = compiled
        return compiled

    def compile_all(self) -> dict:
        """Compile every registered policy. Call once at app startup
        (Aegis.init_app does this automatically) so the hot path only
        ever does dictionary lookups."""
        return {name: self.compile(name) for name in self._policies}

    def _ancestor_chain(self, name: str) -> list:
        chain = []
        seen = set()
        current = name
        while current is not None:
            if current in seen:
                raise PolicyConflictError(
                    f"Circular policy inheritance detected involving {current!r}"
                )
            seen.add(current)
            policy = self.get(current)
            chain.append(policy)
            current = policy.extends
        return list(reversed(chain))

    @staticmethod
    def _validate(compiled: CompiledPolicy) -> None:
        """Feature-dependency checks: e.g. adaptive CAPTCHA needs a risk
        threshold to adapt against; this catches obviously-broken config
        at startup instead of failing silently at request time."""
        if compiled.captcha == "adaptive" and compiled.risk_threshold is None:
            raise ConfigurationError(
                f"Policy {compiled.name!r} uses captcha='adaptive' but has no "
                "risk_threshold configured."
            )
        if compiled.rate_limit is not None:
            try:
                count, _, per = compiled.rate_limit.partition("/")
                int(count)
                if per not in ("second", "minute", "hour", "day"):
                    raise ValueError
            except ValueError:
                raise ConfigurationError(
                    f"Policy {compiled.name!r} has invalid rate_limit "
                    f"{compiled.rate_limit!r}; expected '<n>/<second|minute|hour|day>'"
                ) from None
