# Security Policy

## Supported versions

Flask-Aegis is currently in **alpha (0.x)**. Until 1.0, only the latest
released minor version receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |
| < 0.1   | ❌ |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for suspected security
vulnerabilities in Flask-Aegis itself (as opposed to vulnerabilities in
applications that use it).

Instead:

1. Email `amirpubgplayer1@gmail.com` with a description of the issue, affected
   version(s), and — if possible — a minimal reproduction.
2. You should receive an acknowledgment within 3 business days.
3. We will work with you on a coordinated disclosure timeline. We ask for
   90 days before public disclosure, though we aim to ship a fix well
   before that.

If the report concerns a specific detection rule producing an unsafe
false negative (i.e. a real attack pattern Flask-Aegis fails to catch),
please still report it privately — publishing bypass techniques before a
fix ships puts every Flask-Aegis user at risk.

## Scope

In scope:

- The `flask_aegis` package itself: policy resolution, rule detection
  logic, the decision/risk engines, rate limiting, CAPTCHA handling,
  header hardening, and the CLI.
- Documentation that leads users into an insecure configuration by
  following it as written.

Out of scope:

- Vulnerabilities in your application logic that Flask-Aegis was never
  configured to check for (e.g. a business-logic flaw with no relevant
  policy enabled).
- Vulnerabilities in third-party CAPTCHA providers, Redis, or other
  infrastructure Flask-Aegis integrates with but does not control.
- Denial of service via resource exhaustion of *your own* infrastructure
  when Flask-Aegis is deliberately configured permissively (e.g.
  `profile="minimal"` with no rate limiting).

## Design commitments relevant to security review

- Detection rules never execute attacker-controlled input; all matching
  is done with fixed regular expressions and string operations.
- CAPTCHA secret keys are only ever read inside a provider's `verify()`
  method and are never included in a provider's `public_config()`, in
  Jinja rendering, or in any event/log payload (see `events.py`'s
  redaction list).
- The event system automatically redacts common sensitive field names
  before handing events to listeners. This is a best-effort safety net,
  not a substitute for reviewing your own custom event handlers.
