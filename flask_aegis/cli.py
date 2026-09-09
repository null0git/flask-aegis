"""
flask_aegis.cli
~~~~~~~~~~~~~~~~~

``flask aegis ...`` developer diagnostics commands. Registered
automatically by ``Aegis.init_app`` — no extra setup required.
"""
from __future__ import annotations

import click
from flask import current_app
from flask.cli import with_appcontext

from .profiles import PROFILES


def _get_aegis():
    aegis = current_app.extensions.get("aegis")
    if aegis is None:
        raise click.ClickException(
            "Flask-Aegis is not initialized on this app. Call "
            "Aegis(app, ...) or aegis.init_app(app) first."
        )
    return aegis


@click.group("aegis")
def aegis_cli():
    """Flask-Aegis diagnostics and audit commands."""


@aegis_cli.group("config", invoke_without_command=True)
@click.pass_context
def config_group(ctx):
    """Show or export the active configuration."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(config_show)


@config_group.command("show")
@with_appcontext
def config_show():
    """Show the active profile and enforcement mode."""
    aegis = _get_aegis()
    click.echo(f"Profile:  {aegis.profile_name}")
    click.echo(f"Mode:     {aegis.mode}")
    click.echo(f"Ruleset:  {aegis.ruleset}")
    click.echo(f"Policies: {len(aegis._compiled)} compiled")


@config_group.command("export")
@click.option("--format", "fmt", type=click.Choice(["yaml", "json"]), default="yaml", show_default=True)
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write to a file instead of stdout.")
@with_appcontext
def config_export(fmt, output):
    """Export the compiled configuration (profile, mode, ruleset,
    every policy's resolved settings, security headers, and which
    CAPTCHA provider is active) as YAML or JSON.

    Never includes secrets: the CAPTCHA provider's name is exported,
    its site/secret keys are not; SECRET_KEY is never touched.
    """
    from .config_export import export_config

    aegis = _get_aegis()
    data = export_config(aegis)

    if fmt == "json":
        import json
        text = json.dumps(data, indent=2, default=str)
    else:
        import yaml
        text = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)

    if output:
        with open(output, "w") as f:
            f.write(text)
        click.echo(f"Wrote configuration to {output}")
    else:
        click.echo(text)


@aegis_cli.command("profile")
@click.argument("action", type=click.Choice(["show", "list"]))
@click.argument("name", required=False)
def profile_cmd(action, name):
    """Show what a built-in profile enables: `flask aegis profile show strict`."""
    if action == "list":
        for pname in PROFILES:
            click.echo(pname)
        return

    if not name:
        raise click.ClickException("Usage: flask aegis profile show <name>")
    if name not in PROFILES:
        raise click.ClickException(
            f"Unknown profile {name!r}. Known profiles: {', '.join(PROFILES)}"
        )
    profile = PROFILES[name]
    click.echo(f"Profile: {name}")
    click.echo(f"  {profile.get('description', '')}\n")
    for key, value in profile.items():
        if key == "description":
            continue
        click.echo(f"  {key:<15} {value}")


@aegis_cli.command("rules")
@with_appcontext
def rules_cmd():
    """List every registered detection rule with its metadata."""
    aegis = _get_aegis()
    for rule in aegis.rules.all():
        m = rule.meta
        click.echo(f"{m.rule_id}  [{m.severity}]  ({m.category})")
        click.echo(f"  {m.description}")
        click.echo()


@aegis_cli.command("routes")
@with_appcontext
def routes_cmd():
    """Show the effective, compiled security policy for every route."""
    aegis = _get_aegis()
    for endpoint, policy in aegis._compiled.items():
        if endpoint.startswith("__ratelimit__"):
            continue
        click.echo(endpoint)
        click.echo(f"  CSRF:        {policy.csrf}")
        click.echo(f"  XSS:         {policy.xss}")
        click.echo(f"  SQLi:        {policy.sqli}")
        click.echo(f"  Traversal:   {policy.traversal}")
        click.echo(f"  Rate limit:  {policy.rate_limit}")
        click.echo(f"  CAPTCHA:     {policy.captcha}")
        click.echo(f"  Risk thresh: {policy.risk_threshold}")
        click.echo()


@aegis_cli.command("events")
@with_appcontext
def events_cmd():
    """Placeholder for streaming/inspecting recent security events.

    Wire this up to your event storage (a DB table, a log file, Redis)
    to give operators a live view without a separate dashboard.
    """
    click.echo(
        "flask aegis events shows nothing by default -- subscribe to "
        "events with @aegis.on('security_event') and persist them "
        "somewhere queryable, then extend this command to read from it."
    )


@aegis_cli.command("audit")
@click.option("--ci", is_flag=True, help="Exit non-zero if critical/high findings exist.")
@with_appcontext
def audit_cmd(ci):
    """Run a static configuration audit against the current app."""
    app = current_app
    aegis = _get_aegis()

    findings = []  # (severity, message)

    if app.config.get("DEBUG"):
        findings.append(("critical", "DEBUG=True in app config"))
    if not app.config.get("SECRET_KEY"):
        findings.append(("critical", "No SECRET_KEY configured"))

    # CORS misconfiguration: a wildcard Access-Control-Allow-Origin
    # combined with credentials support lets any origin read
    # cookie-authenticated responses -- the two settings are individually
    # fine but dangerous together. Checks common Flask-CORS config keys
    # if present; silently skips if Flask-CORS (or an equivalent) isn't
    # in use, since app.config won't have these keys at all in that case.
    cors_origins = app.config.get("CORS_ORIGINS")
    cors_supports_credentials = app.config.get("CORS_SUPPORTS_CREDENTIALS")
    if cors_supports_credentials and (cors_origins == "*" or cors_origins is None):
        findings.append((
            "critical",
            "CORS_SUPPORTS_CREDENTIALS is enabled with a wildcard/unset "
            "CORS_ORIGINS -- this allows any website to make "
            "credentialed (cookie-authenticated) requests to this API "
            "and read the response. Set CORS_ORIGINS to an explicit "
            "allowlist of trusted origins.",
        ))

    for endpoint, policy in aegis._compiled.items():
        if endpoint.startswith("__ratelimit__"):
            continue
        if policy.rate_limit is None:
            findings.append(("medium", f"{endpoint} has no rate limit"))
        if not policy.csrf and endpoint not in ("minimal", "api"):
            findings.append(("low", f"{endpoint} has CSRF disabled"))
        if policy.captcha in ("always", "adaptive") and aegis.captcha_provider.name == "null":
            findings.append((
                "critical",
                f"{endpoint} requires CAPTCHA (captcha={policy.captcha!r}) but no "
                f"CAPTCHA provider is configured -- every challenged request will "
                f"fail verification and be permanently blocked. Configure "
                f"captcha={{'provider': ...}} on Aegis(), or set captcha=None on "
                f"this policy.",
            ))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    click.echo("Flask-Aegis Security Audit\n")
    for severity, message in findings:
        counts[severity] += 1
        marker = "\u2717" if severity in ("critical", "high") else "\u26a0"
        click.echo(f"{marker} [{severity.upper()}] {message}")

    click.echo()
    click.echo(f"Critical: {counts['critical']}")
    click.echo(f"High:     {counts['high']}")
    click.echo(f"Medium:   {counts['medium']}")
    click.echo(f"Low:      {counts['low']}")

    if ci and (counts["critical"] or counts["high"]):
        raise SystemExit(1)


@aegis_cli.command("benchmark")
@click.option("--iterations", default=500, show_default=True,
              help="Requests per configuration (after warmup).")
@click.option("--warmup", default=50, show_default=True,
              help="Warmup requests discarded before timing starts.")
def benchmark_cmd(iterations, warmup):
    """Compare bare Flask vs. Flask-Aegis at each built-in profile.

    Measures request latency through Flask's own test client -- this
    isolates Flask-Aegis's added per-request overhead from network/WSGI-
    server variables, which are identical across every configuration
    compared here and so cancel out. It answers "how much does
    Flask-Aegis add," not "what RPS will my production server serve" --
    use a real load-testing tool against a real deployment for that.
    """
    from .benchmark import format_results_table, run_comparison

    click.echo(f"Running {iterations} iterations per configuration ({warmup} warmup each)...\n")
    results = run_comparison(iterations=iterations, warmup=warmup)
    click.echo(format_results_table(results))
    click.echo(
        "\nNote: 'minimal' still shows non-zero overhead vs. bare Flask "
        "despite taking the fast path (the view function itself runs "
        "completely unwrapped) -- the remaining delta is the global "
        "security-headers after_request hook, which runs on every "
        "response regardless of per-route policy. Per-route rule/risk/"
        "rate-limit engine overhead is genuinely zero for a no-op policy."
    )


@aegis_cli.command("ruleset")
@click.argument("action", type=click.Choice(["list", "show"]))
@click.argument("name", required=False)
def ruleset_cmd(action, name):
    """List available rulesets or show which rules a ruleset includes:
    `flask aegis ruleset show 2025-baseline`."""
    from .rulesets import list_rulesets

    rulesets = list_rulesets()
    if action == "list":
        for rs_name, rule_ids in rulesets.items():
            click.echo(f"{rs_name}  ({len(rule_ids)} rules)")
        return

    if not name:
        raise click.ClickException("Usage: flask aegis ruleset show <name>")
    if name not in rulesets:
        raise click.ClickException(
            f"Unknown ruleset {name!r}. Known rulesets: {', '.join(sorted(rulesets))}"
        )
    click.echo(f"Ruleset: {name}")
    for rule_id in rulesets[name]:
        click.echo(f"  {rule_id}")


@aegis_cli.command("playground")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address. Never use 0.0.0.0 or expose this publicly.")
@click.option("--port", default=5050, show_default=True)
@click.option("--debug", is_flag=True, help="Run with the Flask debug reloader.")
def playground_cmd(host, port, debug):
    """Launch the interactive playground: a browser-based UI to test every
    attack class Flask-Aegis detects, side by side with the identical
    payload against unprotected code.

    Local testing only -- see flask_aegis/playground/attacks.py for the
    containment model (SQLi runs against in-memory SQLite, traversal is
    confined to a temp sandbox, command injection and XXE resolution are
    simulated rather than actually executed).
    """
    from .playground import create_app

    app = create_app()
    url = f"http://{host}:{port}"
    click.echo(f"Flask-Aegis playground running at {url}")
    click.echo("Local testing only -- do not expose this publicly. Press CTRL+C to stop.")

    # Deliberately NOT app.run(): Flask's CLI machinery detects a nested
    # app.run() call made from within a `flask <command>` invocation and
    # silently no-ops it ("Ignoring a call to 'app.run()' that would
    # block the current 'flask' CLI command") -- discovered by actually
    # launching this command as a subprocess and finding the server never
    # came up. werkzeug.serving.run_simple is the lower-level API
    # Flask's own app.run() calls internally, and isn't subject to that
    # CLI guard.
    from werkzeug.serving import run_simple
    run_simple(host, port, app, use_reloader=debug, use_debugger=debug)
