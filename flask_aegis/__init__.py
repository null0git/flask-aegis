"""
flask_aegis
~~~~~~~~~~~~~

Fast, modular, policy-driven application security for Flask.

    from flask import Flask
    from flask_aegis import Aegis

    app = Flask(__name__)
    aegis = Aegis(app, profile="standard")

See the README for the full architecture and configuration guide.
"""
from __future__ import annotations

import dataclasses
import functools
from typing import Callable, Optional

from flask import g, request, current_app

from .captcha import build_provider, register_provider as _register_captcha_provider
from .business import ActionPolicy, BusinessRules, BusinessRuleViolation
from .context import RequestContext
from .decisions import Decision, DecisionEngine, Finding, Verdict
from .events import EventBus, SecurityEvent
from .exceptions import AegisBlocked, ConfigurationError
from .headers import HeaderConfig, SecurityHeaders
from .policy import CompiledPolicy, Policy, PolicyEngine, RULE_CATEGORY_FIELDS
from .profiles import get_profile
from .ratelimit import MemoryBackend, RateLimiter
from .risk import RiskEngine
from .rules import RuleRegistry
from .rulesets import build_registry
from .sanitize import sanitize_csv_field, sanitize_html
from .ssrf import SSRFGuard

# Maps a rule_id to the sanitizer function applied when that rule's
# finding carries a SANITIZE decision (see `field(..., xss_action="sanitize")`
# and the CSV injection rule, which defaults to SANITIZE). Extend this by
# calling Aegis.register_sanitizer(rule_id, fn).
_RULE_SANITIZERS = {
    "AEGIS-XSS-001": sanitize_html,
    "AEGIS-CSV-001": sanitize_csv_field,
}

__version__ = "0.7.2"

__all__ = [
    "Aegis", "Policy", "Decision", "Finding", "Verdict",
    "CompiledPolicy", "RuleRegistry", "ActionPolicy", "BusinessRuleViolation",
    "SSRFGuard",
]


class Aegis:
    """The Flask-Aegis extension object.

    Supports both direct and factory-pattern initialization:

        aegis = Aegis(app, profile="standard")

        # or

        aegis = Aegis()
        aegis.init_app(app, profile="standard")
    """

    def __init__(
        self,
        app=None,
        profile: str = "standard",
        mode: str = "enforce",
        captcha: Optional[dict] = None,
        ruleset: str = "latest",
        rate_limit_backend=None,
    ):
        self.profile_name = profile
        self.mode = mode
        self.ruleset = ruleset

        self.rules = build_registry(ruleset)
        self.decision_engine = DecisionEngine(mode=mode)
        self.risk_engine = RiskEngine()
        self.rate_limiter = RateLimiter(rate_limit_backend or MemoryBackend())
        self.events = EventBus()
        self.security_headers = SecurityHeaders()
        self.captcha_provider = build_provider(captcha or {})
        self.business_rules = BusinessRules(rate_limiter=RateLimiter(rate_limit_backend or MemoryBackend()))
        self.ssrf = SSRFGuard()

        self._policy_engine: Optional[PolicyEngine] = None
        self._route_policies: dict[str, str] = {}       # endpoint -> policy name
        self._field_options: dict[str, dict] = {}         # "route:field" -> options
        self._compiled: dict[str, CompiledPolicy] = {}
        self._initialized = False

        self.app = app
        if app is not None:
            self.init_app(app, profile=profile, mode=mode, captcha=captcha)

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def init_app(self, app, profile: Optional[str] = None, mode: Optional[str] = None,
                 captcha: Optional[dict] = None, ruleset: Optional[str] = None) -> None:
        if profile is not None:
            self.profile_name = profile
        if mode is not None:
            self.mode = mode
            self.decision_engine = DecisionEngine(mode=mode)
        if captcha is not None:
            self.captcha_provider = build_provider(captcha)
        if ruleset is not None:
            self.ruleset = ruleset
            self.rules = build_registry(ruleset)

        defaults = get_profile(self.profile_name)
        self._policy_engine = PolicyEngine(profile_defaults=defaults)
        # Every profile is also registered as a usable policy name, so
        # `@aegis.protect("strict")` works even without an explicit
        # add_policy() call.
        for name in ("minimal", "standard", "strict", "api", "public_form",
                     "authentication", "file_upload", "admin", "high_security"):
            self._policy_engine.add(Policy(name=name, **get_profile(name)))

        app.extensions = getattr(app, "extensions", {})
        app.extensions["aegis"] = self

        app.after_request(self._apply_response_security)
        app.errorhandler(AegisBlocked)(self._handle_blocked)
        app.errorhandler(BusinessRuleViolation)(self._handle_business_violation)
        app.jinja_env.globals["aegis"] = self

        try:
            from .cli import aegis_cli
            app.cli.add_command(aegis_cli)
        except Exception:  # pragma: no cover - CLI is optional sugar
            pass

        self._register_static_blueprint(app)

        self.app = app
        self._initialized = True
        # Compile everything now, once, so the request path never resolves
        # inheritance/profile-merging again (see policy.py's fast-path note).
        self._compiled = self._policy_engine.compile_all()

    # ------------------------------------------------------------------
    # Policy configuration API
    # ------------------------------------------------------------------
    def add_policy(self, name: str, extends: Optional[str] = None,
                    priority: int = 0, condition=None, **settings) -> Policy:
        """Register (or replace) a named policy.

        Example
        -------
        >>> aegis.add_policy(
        ...     "registration",
        ...     csrf=True, xss=True, rate_limit="10/minute",
        ...     captcha="adaptive", risk_threshold=60,
        ... )

        Keyword arguments that don't match a built-in category (or any
        other `Policy` field) are routed into the policy's `extra` dict
        rather than raising -- this is what lets a category registered
        by a third-party rule (`aegis.register_detector(...)`, see
        `docs/PLUGINS.md`) be enabled the same way a built-in one is,
        without that category needing to be one of the fixed fields
        `Policy` ships with:

        >>> aegis.register_detector(MyCustomRule())  # category="my_check"
        >>> aegis.add_policy("signup", my_check=True, rate_limit="10/minute")
        """
        known_fields = {f.name for f in dataclasses.fields(Policy)}
        policy_kwargs = {}
        extra = {}
        for key, value in settings.items():
            if key in known_fields:
                policy_kwargs[key] = value
            else:
                extra[key] = value

        policy = Policy(name=name, extends=extends, priority=priority,
                         condition=condition, extra=extra, **policy_kwargs)
        self._require_engine().add(policy)
        if self._initialized:
            self._compiled = self._policy_engine.compile_all()
        return policy

    def field(self, route: str, field_name: str, **options) -> None:
        """Configure per-field behavior for a route. ``route`` matches
        against either the view function's name or its URL path
        (leading slash optional, both forms work interchangeably) --
        whichever you find more readable:

        >>> aegis.field("/register", "bio", max_length=5000, html=True)
        >>> aegis.field("register", "username", max_length=32, xss=True)
        """
        key = route.lstrip("/")
        self._field_options[f"{key}:{field_name}"] = options

    def rate_limit(self, route: str, spec: str, scope: str = "ip") -> None:
        """Attach a standalone rate limit to a route without a full policy."""
        self.add_policy(f"__ratelimit__{route}", rate_limit=spec)
        self._route_policies.setdefault(route, f"__ratelimit__{route}")

    def headers(self, **overrides) -> None:
        """Configure global security headers, e.g.

        >>> aegis.headers(csp=True, hsts=True, nosniff=True,
        ...                frame_protection="SAMEORIGIN")
        """
        self.security_headers.configure(**overrides)

    # ------------------------------------------------------------------
    # Plugin registration
    # ------------------------------------------------------------------
    def register_detector(self, rule) -> None:
        """Register a custom detection rule (must subclass
        :class:`flask_aegis.rules.base.Rule`)."""
        self.rules.register(rule)

    def register_provider(self, name: str, provider_cls) -> None:
        """Register a custom CAPTCHA provider class under ``name`` so it
        can be selected via ``Aegis(app, captcha={"provider": name, ...})``."""
        _register_captcha_provider(name, provider_cls)

    def on(self, event_name: str):
        """Subscribe to security events, e.g.

        >>> @aegis.on("security_event")
        ... def handle(event):
        ...     print(event)
        """
        return self.events.on(event_name)

    # ------------------------------------------------------------------
    # Route protection
    # ------------------------------------------------------------------
    def protect(self, policy_name: str) -> Callable:
        """Decorator attaching a named policy to a view function.

        >>> @aegis.protect("registration")
        ... @app.post("/register")
        ... def register():
        ...     ...

        If the resolved policy is a no-op (nothing enabled), the view is
        returned completely unwrapped — this is the "fast path" described
        in the README: routes with no applicable security features pay
        zero overhead.
        """
        compiled = self._resolve_policy(policy_name)

        def decorator(view_func: Callable) -> Callable:
            if compiled.is_noop:
                return view_func

            @functools.wraps(view_func)
            def wrapped(*args, **kwargs):
                self._run_pipeline(compiled, view_func.__name__)
                return view_func(*args, **kwargs)

            return wrapped

        return decorator

    def protect_action(self, action_name: str, quota: Optional[str] = None,
                        dedupe_header: Optional[str] = None,
                        identity: Optional[Callable[[], str]] = None) -> Callable:
        """Decorator enforcing business-logic rules (quota, replay
        protection) for a named action, independent of the request-security
        policy attached via :meth:`protect`. Can be stacked with it.

        >>> @app.post("/transfer")
        ... @aegis.protect_action(
        ...     "transfer", quota="10/day", dedupe_header="Idempotency-Key",
        ...     identity=lambda: session["user_id"],
        ... )
        ... def transfer():
        ...     ...

        Raises :class:`~flask_aegis.business.BusinessRuleViolation` (caught
        by the same error handling as security blocks) when a quota is
        exceeded or a duplicate request is detected via the dedupe header.
        """
        self.business_rules.add(ActionPolicy(
            name=action_name, quota=quota, dedupe_header=dedupe_header, identity=identity,
        ))

        def decorator(view_func: Callable) -> Callable:
            @functools.wraps(view_func)
            def wrapped(*args, **kwargs):
                self.business_rules.enforce(action_name, request)
                return view_func(*args, **kwargs)

            return wrapped

        return decorator

    def captcha(self) -> str:
        """Render the configured CAPTCHA widget for use in Jinja templates:
        ``{{ aegis.captcha() }}``. Only the provider's public config
        (site key, provider name) ever reaches the template."""
        return self.captcha_provider.render_jinja()

    def captcha_public_config(self) -> dict:
        """Safe-to-serialize CAPTCHA config for non-Jinja frontends
        (React, Vue, mobile) to fetch via an API endpoint."""
        return self.captcha_provider.public_config()

    def sanitized(self, field_name: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieve the sanitized version of a field that triggered a
        SANITIZE-decision finding during this request (e.g. an XSS
        finding on a field configured with ``xss_action="sanitize"``).
        Returns ``default`` if the field wasn't sanitized this request
        (either because it was clean, or because it wasn't flagged at all).

        >>> @aegis.protect("comments")
        ... @app.post("/comment")
        ... def comment():
        ...     body = aegis.sanitized("body", default=request.form.get("body", ""))
        ...     save_comment(body)
        """
        return getattr(g, "aegis_sanitized", {}).get(field_name, default)

    def register_sanitizer(self, rule_id: str, fn: Callable[[str], str]) -> None:
        """Register (or replace) the sanitizer function applied when a
        finding from ``rule_id`` carries a SANITIZE decision.

        >>> aegis.register_sanitizer("AEGIS-XSS-001", my_custom_sanitizer)
        """
        _RULE_SANITIZERS[rule_id] = fn

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------
    def _resolve_policy(self, name: str) -> CompiledPolicy:
        if self._initialized:
            try:
                return self._compiled[name]
            except KeyError:
                raise ConfigurationError(
                    f"No policy named {name!r} is registered. Call "
                    f"aegis.add_policy({name!r}, ...) before using "
                    f"@aegis.protect({name!r})."
                ) from None
        # Not initialized yet (e.g. decorator applied before init_app in a
        # factory pattern) — defer resolution until first request.
        return self._require_engine().compile(name) if self._policy_engine else None

    def _require_engine(self) -> PolicyEngine:
        if self._policy_engine is None:
            # Allow add_policy() before init_app(), using bare defaults.
            self._policy_engine = PolicyEngine()
        return self._policy_engine

    def _run_pipeline(self, policy: CompiledPolicy, endpoint: str) -> None:
        ctx = RequestContext.from_flask_request(
            request, field_options=self._field_options_for(endpoint)
        )

        if policy.condition is not None and not policy.condition(request):
            return

        findings: list[Finding] = []
        risk_ctx = self.risk_engine.new_context()

        # 1. Rate limiting
        if policy.rate_limit:
            result = self.rate_limiter.check(ctx.identity, policy.rate_limit)
            if not result.allowed:
                findings.append(Finding(
                    rule_id="AEGIS-RATE-001",
                    decision=Decision.THROTTLE,
                    message="Rate limit exceeded",
                    severity="medium",
                    score=30,
                    meta={"retry_after": result.reset_after},
                ))
                risk_ctx.add("rate_limit_violation")

        # 2. Security rules (only the categories this policy enables)
        for category in RULE_CATEGORY_FIELDS:
            if not getattr(policy, category):
                continue
            for rule in self.rules.for_category(category):
                if not rule.applies_to(ctx):
                    continue
                finding = rule.check(ctx)
                if finding is not None:
                    findings.append(finding)
                    risk_ctx.add("suspicious_input", meta={"rule": finding.rule_id})

        # 2a. Custom (plugin) rule categories -- registered via
        # aegis.register_detector() with a category name that isn't one
        # of the built-in RULE_CATEGORY_FIELDS. These are enabled via
        # policy.extra (see Aegis.add_policy's docstring) rather than a
        # fixed Policy dataclass field, since a plugin's category name
        # isn't known when Policy itself is defined.
        for category in self.rules.categories():
            if category in RULE_CATEGORY_FIELDS or not policy.extra.get(category):
                continue
            for rule in self.rules.for_category(category):
                if not rule.applies_to(ctx):
                    continue
                finding = rule.check(ctx)
                if finding is not None:
                    findings.append(finding)
                    risk_ctx.add("suspicious_input", meta={"rule": finding.rule_id})

        # 2b. Apply sanitization for any SANITIZE-decision findings. Unlike
        # BLOCK/THROTTLE/CHALLENGE, a SANITIZE finding never stops the
        # request -- it produces a cleaned value the view can retrieve
        # with `aegis.sanitized(field_name)` instead of the raw input.
        sanitized = {}
        for finding in findings:
            if finding.decision is not Decision.SANITIZE:
                continue
            field_name = finding.meta.get("field")
            sanitizer = _RULE_SANITIZERS.get(finding.rule_id)
            if field_name and sanitizer:
                raw_value = ctx.text_values.get(field_name, "")
                sanitized[field_name] = sanitizer(raw_value)
        if sanitized:
            g.aegis_sanitized = sanitized

        # 3. CAPTCHA (only reached if policy calls for it and risk warrants it)
        if policy.captcha == "always" or (
            policy.captcha == "adaptive" and risk_ctx.score >= policy.risk_threshold
        ):
            token = request.form.get("aegis_captcha_token") or request.headers.get("X-Captcha-Token")
            if not self.captcha_provider.verify(token, remote_ip=ctx.remote_addr):
                findings.append(Finding(
                    rule_id="AEGIS-CAPTCHA-001",
                    decision=Decision.CHALLENGE,
                    message="CAPTCHA challenge required or failed",
                    severity="low",
                    score=25,
                ))
                risk_ctx.add("invalid_captcha")

        verdict = self.decision_engine.resolve(findings, risk_score=risk_ctx.score)
        g.aegis_verdict = verdict

        self._emit_events(verdict, endpoint)

        if verdict.decision is Decision.BLOCK:
            top = verdict.top_finding()
            raise AegisBlocked(
                reason=top.message if top else "Blocked by policy",
                rule_id=top.rule_id if top else None,
            )
        if verdict.decision is Decision.CHALLENGE:
            top = verdict.top_finding()
            raise AegisBlocked(
                reason=top.message if top else "Challenge required",
                rule_id=top.rule_id if top else None,
                status=428,  # Precondition Required
            )
        if verdict.decision is Decision.THROTTLE:
            top = verdict.top_finding()
            raise AegisBlocked(
                reason=top.message if top else "Rate limit exceeded",
                rule_id=top.rule_id if top else None,
                status=429,  # Too Many Requests
            )
        # LOG / SANITIZE / ALLOW all fall through to the view — these are
        # soft signals recorded via events + risk score, not hard stops.

    def _field_options_for(self, endpoint: str) -> dict:
        # Field keys are stored with their leading slash stripped (see
        # `field()`), so normalize both possible match targets the same
        # way: the view function's name, and the request path.
        candidates = {endpoint.lstrip("/"), request.path.lstrip("/")}
        result = {}
        for key, opts in self._field_options.items():
            route_part, _, field_name = key.partition(":")
            if route_part in candidates:
                result[field_name] = opts
        return result

    def _emit_events(self, verdict: Verdict, endpoint: str) -> None:
        if verdict.decision is Decision.ALLOW:
            return
        for finding in verdict.findings:
            event = SecurityEvent(
                event="request_blocked" if verdict.decision is Decision.BLOCK else "security_finding",
                route=endpoint,
                severity=finding.severity,
                action=str(verdict.decision),
                rule=finding.rule_id,
                risk_score=verdict.risk_score,
                meta=finding.meta,
            )
            self.events.emit("security_event", event.to_dict())

    def _handle_blocked(self, error: AegisBlocked):
        from flask import jsonify
        payload = {"error": "blocked_by_aegis", "reason": error.reason}
        if error.rule_id:
            payload["rule"] = error.rule_id
        return jsonify(payload), error.status

    def _handle_business_violation(self, error: BusinessRuleViolation):
        from flask import jsonify
        status = 409 if error.reason == "duplicate_request" else 429
        return jsonify(error=f"business_rule_{error.reason}", reason=error.message), status

    def _apply_response_security(self, response):
        return self.security_headers.apply(response)

    @staticmethod
    def _register_static_blueprint(app) -> None:
        """Registers a blueprint serving the frontend sanitization module
        (`aegis-sanitize.js`) at `/_aegis/static/aegis-sanitize.js`, so
        templates can do:

            <script src="{{ url_for('aegis_static.static',
                                     filename='aegis-sanitize.js') }}"></script>

        Skipped silently if a blueprint with this name is already
        registered (e.g. Aegis.init_app called twice on the same app).
        """
        if "aegis_static" in app.blueprints:
            return
        import os
        from flask import Blueprint

        static_dir = os.path.join(os.path.dirname(__file__), "static")
        blueprint = Blueprint(
            "aegis_static", __name__,
            static_folder=static_dir, static_url_path="/_aegis/static",
        )
        app.register_blueprint(blueprint)
