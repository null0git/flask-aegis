"""
examples/vulnerable_app/app.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

⚠️  FOR LOCAL SECURITY TESTING ONLY. NEVER DEPLOY THIS APPLICATION. ⚠️

Every route in this app comes in a pair:

  /vuln/<name>       -- deliberately vulnerable, NO Flask-Aegis protection.
  /protected/<name>  -- the same vulnerable code pattern, WITH
                         @aegis.protect(...) attached.

The point is to demonstrate, against real (if contained) vulnerable
code, what Flask-Aegis catches and what it doesn't -- not to provide a
general-purpose exploitation target. See tests/security/test_vulnerable_app.py
for the assertions this app exists to support.

Containment choices made on purpose:
  - SQLi uses an in-memory SQLite database seeded with fake data --
    nothing outside this process is at risk.
  - Path traversal is confined to a temporary sandbox directory created
    at startup and torn down on exit -- it cannot read real files
    outside that sandbox.
  - SSTI genuinely evaluates Jinja server-side (that's what SSTI is) --
    this can execute arbitrary Python via Jinja's sandbox-escape
    gadgets on your local machine. Only run this against 127.0.0.1,
    never expose it, and don't run it on a machine with anything
    sensitive on it.
  - Command injection is SIMULATED, not real: the "vulnerable" sink is
    a fake shell executor that returns a string describing what it
    would have run, and never calls subprocess/os.system. This keeps
    the demo meaningful (you can still see exactly what payload would
    have reached a real shell) without the app being able to actually
    execute anything on your machine.

Run:
    pip install -e ../..
    python app.py
    # then, in another terminal:
    curl "http://127.0.0.1:5001/vuln/xss?name=<script>alert(1)</script>"
    curl "http://127.0.0.1:5001/protected/xss?name=<script>alert(1)</script>"
"""
import os
import shutil
import sqlite3
import tempfile

from flask import Flask, jsonify, request, render_template_string

from flask_aegis import Aegis
from flask_aegis.rules.traversal import safe_join_root

app = Flask(__name__)
app.config["SECRET_KEY"] = "local-testing-only-do-not-reuse"

aegis = Aegis(app, profile="strict", mode="enforce")
aegis.add_policy(
    "vuln_test",
    extends="strict",
    rate_limit="1000/minute",  # high, so the demo isn't rate-limited mid-testing
    captcha=None,
)

# ---------------------------------------------------------------------------
# Contained fixtures
# ---------------------------------------------------------------------------

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
_db.executemany(
    "INSERT INTO users (username, email) VALUES (?, ?)",
    [("alice", "alice@example.com"), ("bob", "bob@example.com")],
)
_db.commit()

_sandbox_dir = tempfile.mkdtemp(prefix="aegis-vuln-app-")
_public_dir = os.path.join(_sandbox_dir, "public")
os.makedirs(_public_dir)
with open(os.path.join(_public_dir, "public.txt"), "w") as f:
    f.write("this file is meant to be readable\n")
# Deliberately OUTSIDE the intended serving directory (_public_dir), so
# reaching it actually requires a traversal payload like '../secret.txt'
# -- not just requesting its name directly.
with open(os.path.join(_sandbox_dir, "secret.txt"), "w") as f:
    f.write("this file should NOT be reachable via the file parameter\n")


def _fake_shell_exec(command: str) -> str:
    """Simulated command sink -- never actually executes anything.
    Exists so the command-injection demo shows a realistic payload
    reaching *a* sink, without the app being capable of real RCE."""
    return f"[simulated -- not executed] would run: {command}"


import atexit
atexit.register(lambda: shutil.rmtree(_sandbox_dir, ignore_errors=True))


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

@app.get("/vuln/xss")
def vuln_xss():
    name = request.args.get("name", "world")
    # VULNERABLE: raw interpolation into an HTML response, no escaping.
    return f"<html><body>Hello, {name}!</body></html>"


@app.get("/protected/xss")
@aegis.protect("vuln_test")
def protected_xss():
    name = request.args.get("name", "world")
    return f"<html><body>Hello, {name}!</body></html>"


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

@app.get("/vuln/sqli")
def vuln_sqli():
    username = request.args.get("username", "")
    # VULNERABLE: string-concatenated SQL.
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    try:
        rows = _db.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        return jsonify(error=str(exc), query=query), 400
    return jsonify(query=query, rows=rows)


@app.get("/protected/sqli")
@aegis.protect("vuln_test")
def protected_sqli():
    username = request.args.get("username", "")
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    try:
        rows = _db.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        return jsonify(error=str(exc), query=query), 400
    return jsonify(query=query, rows=rows)


# ---------------------------------------------------------------------------
# Path traversal (confined to a temp sandbox -- see module docstring)
# ---------------------------------------------------------------------------

@app.get("/vuln/traversal")
def vuln_traversal():
    filename = request.args.get("file", "public.txt")
    # VULNERABLE: no validation before joining onto the serving root, so
    # 'file=../secret.txt' escapes _public_dir into _sandbox_dir.
    path = os.path.join(_public_dir, filename)
    try:
        with open(path) as f:
            return jsonify(path=path, content=f.read())
    except OSError as exc:
        return jsonify(error=str(exc), path=path), 400


@app.get("/protected/traversal")
@aegis.protect("vuln_test")
def protected_traversal():
    filename = request.args.get("file", "public.txt")
    path = os.path.join(_public_dir, filename)
    try:
        with open(path) as f:
            return jsonify(path=path, content=f.read())
    except OSError as exc:
        return jsonify(error=str(exc), path=path), 400


@app.get("/safe/traversal")
def safe_traversal():
    """The actually-correct fix, for comparison: validate with
    safe_join_root regardless of whether Aegis is attached."""
    filename = request.args.get("file", "public.txt")
    resolved = safe_join_root(_public_dir, filename)
    if resolved is None:
        return jsonify(error="rejected: path escapes sandbox"), 400
    with open(resolved) as f:
        return jsonify(path=resolved, content=f.read())


# ---------------------------------------------------------------------------
# SSTI -- genuinely evaluates Jinja. Local-only. See module docstring.
# ---------------------------------------------------------------------------

@app.get("/vuln/ssti")
def vuln_ssti():
    template = request.args.get("template", "Hello, world!")
    # VULNERABLE: user input treated as template *source*, not data.
    return render_template_string(template)


@app.get("/protected/ssti")
@aegis.protect("vuln_test")
def protected_ssti():
    template = request.args.get("template", "Hello, world!")
    return render_template_string(template)


# ---------------------------------------------------------------------------
# Command injection -- simulated sink, never actually executes anything.
# ---------------------------------------------------------------------------

@app.get("/vuln/cmdi")
def vuln_cmdi():
    host = request.args.get("host", "example.com")
    # VULNERABLE PATTERN (simulated): would be `ping -c 1 {host}` via a
    # real shell in a real app. Here it only returns a description.
    result = _fake_shell_exec(f"ping -c 1 {host}")
    return jsonify(result=result)


@app.get("/protected/cmdi")
@aegis.protect("vuln_test")
def protected_cmdi():
    host = request.args.get("host", "example.com")
    result = _fake_shell_exec(f"ping -c 1 {host}")
    return jsonify(result=result)


if __name__ == "__main__":
    print(f"Sandbox directory: {_sandbox_dir}")
    print("Binding to 127.0.0.1 only. Do not expose this app publicly.")
    app.run(host="127.0.0.1", port=5001, debug=False)
