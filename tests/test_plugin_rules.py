from flask import Flask, jsonify

from flask_aegis import Aegis
from flask_aegis.decisions import Decision, Finding
from flask_aegis.rules.base import Rule, RuleMeta


class _NoEmojiRule(Rule):
    meta = RuleMeta(
        rule_id="TEST-NOEMOJI-001", category="no_emoji", severity="low",
        description="d", mitigation="m", false_positive_notes="f", limitations="l",
    )

    def check(self, ctx):
        value = ctx.text_values.get("username", "")
        if any(0x1F300 <= ord(c) <= 0x1FAFF for c in value):
            return Finding(rule_id=self.meta.rule_id, decision=Decision.BLOCK, message="emoji found")
        return None


def _build_app():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", TESTING=True)
    aegis = Aegis(app, profile="minimal")
    aegis.register_detector(_NoEmojiRule())
    aegis.add_policy("signup", no_emoji=True, rate_limit="100/minute", captcha=None)

    @app.post("/signup")
    @aegis.protect("signup")
    def signup():
        return jsonify(ok=True)

    return app, aegis


def test_add_policy_routes_unknown_kwarg_into_extra():
    app, aegis = _build_app()
    compiled = aegis._compiled["signup"]
    assert compiled.extra.get("no_emoji") is True


def test_builtin_field_kwarg_still_sets_the_real_field_not_extra():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", TESTING=True)
    aegis = Aegis(app, profile="minimal")
    aegis.add_policy("t", xss=True, rate_limit="10/minute")
    compiled = aegis._compiled["t"]
    assert compiled.xss is True
    assert "xss" not in compiled.extra


def test_custom_rule_category_blocks_via_policy_extra():
    app, aegis = _build_app()
    client = app.test_client()
    resp = client.post("/signup", data={"username": "alice\U0001F389"})
    assert resp.status_code == 403
    assert resp.get_json()["rule"] == "TEST-NOEMOJI-001"


def test_custom_rule_category_allows_clean_input():
    app, aegis = _build_app()
    client = app.test_client()
    resp = client.post("/signup", data={"username": "alice"})
    assert resp.status_code == 200


def test_registered_custom_rule_visible_in_rules_list():
    app, aegis = _build_app()
    ids = {r.meta.rule_id for r in aegis.rules.all()}
    assert "TEST-NOEMOJI-001" in ids


def test_custom_category_not_enabled_stays_silent():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", TESTING=True)
    aegis = Aegis(app, profile="minimal")
    aegis.register_detector(_NoEmojiRule())
    # No add_policy enabling "no_emoji" this time.
    aegis.add_policy("open", rate_limit="100/minute", captcha=None)

    @app.post("/open")
    @aegis.protect("open")
    def open_view():
        return jsonify(ok=True)

    client = app.test_client()
    resp = client.post("/open", data={"username": "alice\U0001F389"})
    assert resp.status_code == 200  # category never enabled -> rule never runs
