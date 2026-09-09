# Changelog

All notable changes to Flask-Aegis are documented here. This project
follows [Semantic Versioning](https://semver.org/) once it reaches 1.0;
until then, minor version bumps may include behavior changes as the
alpha design settles.

## [0.7.0] — Phase 7: type checking, deployment tooling, plugin fix

- `flask_aegis/py.typed` (PEP 561 marker) — verified packaged in a real
  built wheel, alongside the `Typing :: Typed` classifier.
- Second CAPTCHA provider (`HcaptchaProvider`), proving the provider
  interface is genuinely provider-agnostic rather than shaped around
  reCAPTCHA specifically.
- **Fixed a real gap in the plugin architecture**: `aegis.
  register_detector()` let you register a rule with a custom category,
  but nothing let you *enable* that category through the policy
  system — a rule registered this way could never actually fire.
  `aegis.add_policy()` now routes any keyword that isn't a recognized
  built-in field into the policy's `extra` dict automatically, and the
  request pipeline checks `extra` for custom categories, so a plugin
  rule works exactly like a built-in one
  (`aegis.add_policy("signup", my_custom_category=True)`). See
  `docs/PLUGINS.md` and `tests/test_plugin_rules.py`.
- `docs/DEPLOYMENT.md` (WSGI worker count vs. the in-memory rate
  limiter, reverse-proxy `X-Forwarded-For`/TLS considerations) and
  `docs/PLUGINS.md` (full plugin-authoring guide with a verified
  worked example).
- `Dockerfile` / `docker-compose.yml` for the playground;
  `.pre-commit-config.yaml`.

## [0.6.0] — Phase 6: publish readiness

- Verified (not just declared) that `templates/`, `static/`, and the
  playground's assets ship correctly in a real built wheel and survive
  a real `pip install`.
- Added `LICENSE` (MIT), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, this
  changelog, GitHub Actions CI (`.github/workflows/ci.yml`), issue and
  pull-request templates.
- Project logo (`assets/logo/`).

## [0.5.0] — Phase 5: integrations

- `flask_aegis.openapi`: OpenAPI 3.x-derived request validation
  (dependency-free JSON-Schema subset).
- `flask_aegis.graphql`: GraphQL depth/complexity/alias/batch-size
  limits and introspection blocking.
- `flask_aegis.websocket`: library-agnostic WebSocket origin/size/rate/
  connection-count limits.
- `flask aegis config export`: secret-free YAML/JSON configuration
  snapshot. `config` is now a command group (`show`/`export`);
  `flask aegis config` alone keeps its prior behavior.
- Added `pyyaml` as a runtime dependency.

## [0.4.0] — Phase 4: broader attack coverage + playground

- 16 new detection rules across three sub-releases: NoSQL injection,
  XXE, open redirect, HTTP Parameter Pollution (`ruleset="2027"`);
  insecure deserialization, request-field SSRF detection, prototype
  pollution, Expression Language injection (`ruleset="2028"`); mass
  assignment, ReDoS detection, JWT weak-algorithm detection, homograph
  spoofing, XML entity bombs, SSI/LaTeX/format-string injection
  (`ruleset="2029"`, now `"latest"` — 25 rules total).
- Zip-bomb protection in `flask_aegis.upload` (compression-ratio,
  total-size, and file-count caps).
- CORS misconfiguration audit check.
- Interactive playground web app (`flask aegis playground` /
  `python -m flask_aegis.playground`) — all 25 attack classes, live,
  side-by-side against unprotected code.
- Input sanitization: `flask_aegis.sanitize` (backend) +
  `aegis-sanitize.js` (frontend, parity-tested via Node), wired into
  the `SANITIZE` decision path.

## [0.3.0] — Phase 3: professional tooling

- Dependency-free fuzz harnesses (`tests/fuzz/`) for rule crash-safety,
  the `safe_join_root` traversal invariant, and policy-compilation
  determinism.
- `hypothesis`-based property tests (`tests/property/`), optional
  `[dev]` extra.
- Vulnerable test app (`examples/vulnerable_app/`) with a paired
  security test suite proving real exploitation and real blocking.
- Benchmark suite (`flask aegis benchmark`) and `research/` methodology
  docs with captured results.
- Versioned rule sets (`ruleset=`) so new rules never silently change
  behavior for a pinned app.
- Richer `flask aegis audit` checks (CAPTCHA misconfiguration).

## [0.2.0] — Phase 2: attack surface breadth

- SSTI, command injection, LDAP/XPath injection, header/log injection,
  CSV/formula injection detection rules.
- File-upload policy (`flask_aegis.upload`): extension allowlisting,
  double-extension detection, Zip Slip protection.
- SSRF validator utility (`flask_aegis.ssrf.SSRFGuard`).
- Business-logic protection (`flask_aegis.business`): per-action
  quotas, replay/idempotency protection via `@aegis.protect_action`.

## [0.1.0] — Phase 1: core architecture

- Policy engine: inheritance, priorities, conditions, compile-once
  resolution.
- Decision engine (ALLOW/LOG/SANITIZE/THROTTLE/CHALLENGE/BLOCK) with
  enforce/monitor/adaptive modes.
- Risk scoring engine.
- XSS, SQL injection, and path traversal detection rules.
- Rate limiting (memory + Redis backends).
- CAPTCHA (reCAPTCHA v2/v3, frontend-agnostic).
- Security headers and cookie hardening.
- Event system with automatic sensitive-field redaction.
- CLI: `config`, `profile`, `rules`, `routes`, `audit`.
- Fast path: a policy that enables nothing returns the view function
  completely unwrapped.
