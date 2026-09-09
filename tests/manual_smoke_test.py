"""Standalone smoke test (no pytest dependency) exercising the same paths
as the tests/ suite, so we can verify correctness in an offline sandbox."""
import sys
import os; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request
from flask_aegis import Aegis
from flask_aegis.policy import Policy, PolicyEngine
from flask_aegis.exceptions import ConfigurationError, PolicyConflictError
from flask_aegis.decisions import Decision, DecisionEngine, Finding
from flask_aegis.ratelimit import MemoryBackend, RateLimiter
from flask_aegis.rules.xss import XSSRule
from flask_aegis.rules.sqli import SQLiRule
from flask_aegis.rules.traversal import TraversalRule, safe_join_root
from flask_aegis.context import RequestContext

passed = 0
failed = 0

def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"PASS  {name}")
    else:
        failed += 1
        print(f"FAIL  {name}")

# --- Policy engine ---
engine = PolicyEngine()
engine.add(Policy("public_form", csrf=True, xss=True, rate_limit="20/minute"))
engine.add(Policy("registration", extends="public_form", captcha="adaptive", risk_threshold=60))
c = engine.compile("registration")
check("policy inheritance: csrf inherited", c.csrf is True)
check("policy inheritance: captcha overridden", c.captcha == "adaptive")

try:
    engine2 = PolicyEngine()
    engine2.add(Policy("a", extends="b"))
    engine2.add(Policy("b", extends="a"))
    engine2.compile("a")
    check("circular inheritance raises", False)
except PolicyConflictError:
    check("circular inheritance raises", True)

try:
    engine3 = PolicyEngine()
    engine3.add(Policy("bad", rate_limit="garbage"))
    engine3.compile("bad")
    check("invalid rate_limit raises", False)
except ConfigurationError:
    check("invalid rate_limit raises", True)

# --- Decision engine ---
de = DecisionEngine(mode="monitor")
v = de.resolve([Finding("X", Decision.BLOCK, "msg")])
check("monitor mode never blocks", v.decision is Decision.LOG and not v.blocked)

de2 = DecisionEngine(mode="adaptive")
v2 = de2.resolve([Finding("X", Decision.LOG, "msg")], risk_score=95)
check("adaptive mode escalates on high risk", v2.decision is Decision.CHALLENGE)

# --- Rate limiter ---
rl = RateLimiter(MemoryBackend())
allowed_all = all(rl.check("1.2.3.4", "5/minute").allowed for _ in range(5))
blocked_after = not rl.check("1.2.3.4", "5/minute").allowed
check("rate limiter allows up to limit then blocks", allowed_all and blocked_after)

# --- Rules ---
def ctx(**tv):
    return RequestContext(method="POST", path="/t", remote_addr="127.0.0.1", text_values=tv)

check("xss rule detects script tag",
      XSSRule().check(ctx(comment="<script>alert(1)</script>")) is not None)
check("xss rule ignores clean input",
      XSSRule().check(ctx(comment="hello world")) is None)
check("sqli rule detects union select",
      SQLiRule().check(ctx(q="1 UNION SELECT user,pass FROM users")) is not None)
check("sqli rule ignores clean input",
      SQLiRule().check(ctx(q="42")) is None)
check("traversal rule detects raw sequence",
      TraversalRule().check(ctx(file="../../etc/passwd")) is not None)
check("traversal rule detects encoded sequence",
      TraversalRule().check(ctx(file="%2e%2e%2f%2e%2e%2fetc%2fpasswd")) is not None)

import tempfile, os
with tempfile.TemporaryDirectory() as d:
    root = os.path.join(d, "uploads")
    os.makedirs(root)
    check("safe_join_root blocks escape", safe_join_root(root, "../../etc/passwd") is None)
    check("safe_join_root allows valid path", safe_join_root(root, "a", "b.txt") is not None)

# --- Full Flask integration ---
app = Flask(__name__)
app.config.update(SECRET_KEY="test", TESTING=True)
aegis = Aegis(app, profile="standard")
aegis.add_policy("registration", extends="public_form", rate_limit="100/minute", captcha=None)
aegis.add_policy("rl_test", extends="public_form", xss=False, sqli=False, rate_limit="3/minute", captcha=None)

@app.get("/")
def index():
    return jsonify(ok=True)

@app.post("/register")
@aegis.protect("registration")
def register():
    return jsonify(username=request.form.get("username"))

@app.get("/unprotected")
@aegis.protect("minimal")
def unprotected():
    return jsonify(ok=True)

@app.post("/rl-test")
@aegis.protect("rl_test")
def rl_test_view():
    return jsonify(ok=True)

client = app.test_client()

r = client.post("/register", data={"username": "alice"})
check("clean request passes (200)", r.status_code == 200 and r.get_json()["username"] == "alice")

r2 = client.post("/register", data={"username": "<script>alert(1)</script>"})
check("xss payload blocked (403)", r2.status_code == 403 and r2.get_json()["rule"] == "AEGIS-XSS-001")

r3 = client.post("/register", data={"username": "1 UNION SELECT 1,2,3"})
check("sqli payload blocked (403)", r3.status_code == 403 and r3.get_json()["rule"] == "AEGIS-SQLI-001")

for _ in range(3):
    client.post("/rl-test")
r4 = client.post("/rl-test")
check("rate limit triggers after threshold", r4.status_code == 429 and r4.get_json()["rule"] == "AEGIS-RATE-001")

r5 = client.get("/")
check("security headers present", "Content-Security-Policy" in r5.headers
      and r5.headers.get("X-Content-Type-Options") == "nosniff"
      and r5.headers.get("X-Frame-Options") == "DENY")

view = app.view_functions["unprotected"]
check("minimal profile fast path returns unwrapped view", getattr(view, "__wrapped__", None) is None)

events_seen = []
@aegis.on("security_event")
def _capture(event):
    events_seen.append(event)

client.post("/register", data={"username": "<script>y</script>"})
check("event bus fires on block", len(events_seen) == 1 and events_seen[0]["rule"] == "AEGIS-XSS-001")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
