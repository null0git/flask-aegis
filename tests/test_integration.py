import pytest
from flask import Flask, jsonify, request

from flask_aegis import Aegis


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", TESTING=True)

    aegis = Aegis(app, profile="standard")
    aegis.add_policy(
        "registration",
        extends="public_form",
        rate_limit="3/minute",
        captcha=None,  # keep the integration test deterministic
    )

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

    @app.post("/render")
    @aegis.protect("registration")
    def render():
        return jsonify(name=request.form.get("name"))

    aegis.field("comment", "body", xss_action="sanitize")

    @app.post("/comment")
    @aegis.protect("registration")
    def comment():
        stored = aegis.sanitized("body", default=request.form.get("body", ""))
        return jsonify(stored=stored)

    @app.post("/transfer")
    @aegis.protect_action("transfer", quota="2/minute", dedupe_header="Idempotency-Key")
    def transfer():
        return jsonify(ok=True)

    app.aegis = aegis
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_clean_request_passes(client):
    resp = client.post("/register", data={"username": "alice"})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_xss_payload_blocked(client):
    resp = client.post("/register", data={"username": "<script>alert(1)</script>"})
    assert resp.status_code == 403
    body = resp.get_json()
    assert body["rule"] == "AEGIS-XSS-001"


def test_sqli_payload_blocked(client):
    resp = client.post("/register", data={"username": "1 UNION SELECT 1,2,3"})
    assert resp.status_code == 403
    assert resp.get_json()["rule"] == "AEGIS-SQLI-001"


def test_rate_limit_triggers_after_threshold(client):
    for _ in range(3):
        resp = client.post("/register", data={"username": "bob"})
        assert resp.status_code == 200
    resp = client.post("/register", data={"username": "bob"})
    assert resp.status_code == 429
    assert resp.get_json()["rule"] == "AEGIS-RATE-001"


def test_security_headers_present_on_every_response(client):
    resp = client.get("/")
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_minimal_profile_is_fast_path_noop(app):
    # "minimal" profile enables nothing enforceable -> protect() should
    # return the view completely unwrapped.
    view = app.view_functions["unprotected"]
    assert getattr(view, "__wrapped__", None) is None


def test_events_fire_on_block(app, client):
    seen = []

    @app.aegis.on("security_event")
    def _capture(event):
        seen.append(event)

    client.post("/register", data={"username": "<script>x</script>"})
    assert len(seen) == 1
    assert seen[0]["rule"] == "AEGIS-XSS-001"


def test_ssti_payload_blocked(client):
    resp = client.post("/render", data={"name": "{{7*7}}"})
    assert resp.status_code == 403
    assert resp.get_json()["rule"] == "AEGIS-SSTI-001"


def test_clean_render_passes(client):
    resp = client.post("/render", data={"name": "Alice"})
    assert resp.status_code == 200


def test_protect_action_quota_then_replay(client):
    r1 = client.post("/transfer", headers={"Idempotency-Key": "k1"})
    r2 = client.post("/transfer", headers={"Idempotency-Key": "k2"})
    r3 = client.post("/transfer", headers={"Idempotency-Key": "k3"})
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert r3.get_json()["error"] == "business_rule_quota_exceeded"


def test_protect_action_replay_detection(app):
    # Fresh client on the same app but a different action name to avoid
    # quota interference from the previous test's action.
    @app.post("/transfer2")
    @app.aegis.protect_action("transfer2", dedupe_header="Idempotency-Key")
    def transfer2():
        return jsonify(ok=True)

    client = app.test_client()
    r1 = client.post("/transfer2", headers={"Idempotency-Key": "dup"})
    r2 = client.post("/transfer2", headers={"Idempotency-Key": "dup"})
    assert r1.status_code == 200
    assert r2.status_code == 409
    assert r2.get_json()["error"] == "business_rule_duplicate_request"


def test_sanitize_field_allows_request_but_cleans_value(client):
    resp = client.post("/comment", data={"body": "hi <script>alert(1)</script> there <b>bold</b>"})
    assert resp.status_code == 200
    assert resp.get_json()["stored"] == "hi  there <b>bold</b>"


def test_sanitize_field_leaves_clean_input_untouched(client):
    resp = client.post("/comment", data={"body": "just a normal comment"})
    assert resp.status_code == 200
    assert resp.get_json()["stored"] == "just a normal comment"


def test_static_blueprint_serves_frontend_sanitize_module(client):
    resp = client.get("/_aegis/static/aegis-sanitize.js")
    assert resp.status_code == 200
    assert b"AegisSanitize" in resp.data
