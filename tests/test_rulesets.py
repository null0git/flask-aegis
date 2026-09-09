import pytest
from flask import Flask, jsonify, request

from flask_aegis import Aegis
from flask_aegis.exceptions import ConfigurationError
from flask_aegis.rulesets import build_registry, list_rulesets


def test_2025_baseline_has_only_original_three_rules():
    registry = build_registry("2025-baseline")
    ids = {r.meta.rule_id for r in registry.all()}
    assert ids == {"AEGIS-XSS-001", "AEGIS-SQLI-001", "AEGIS-TRAVERSAL-001"}


def test_latest_includes_all_nine_rules():
    registry = build_registry("latest")
    assert len(registry.all()) == 9


def test_2026_and_latest_are_equivalent():
    a = {r.meta.rule_id for r in build_registry("2026").all()}
    b = {r.meta.rule_id for r in build_registry("latest").all()}
    assert a == b


def test_unknown_ruleset_raises_configuration_error():
    with pytest.raises(ConfigurationError):
        build_registry("not-a-real-ruleset")


def test_list_rulesets_reports_correct_counts():
    rulesets = list_rulesets()
    assert len(rulesets["2025-baseline"]) == 3
    assert len(rulesets["2026"]) == 9


def test_pinned_baseline_ruleset_does_not_catch_ssti_end_to_end():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", TESTING=True)
    aegis = Aegis(app, profile="standard", ruleset="2025-baseline")
    aegis.add_policy("t", extends="standard", rate_limit="1000/minute", captcha=None)

    @app.post("/render")
    @aegis.protect("t")
    def render():
        return jsonify(name=request.form.get("name"))

    client = app.test_client()
    resp = client.post("/render", data={"name": "{{7*7}}"})
    assert resp.status_code == 200  # SSTI rule doesn't exist in this ruleset

    resp2 = client.post("/render", data={"name": "<script>alert(1)</script>"})
    assert resp2.status_code == 403  # XSS rule is still in the baseline
    assert resp2.get_json()["rule"] == "AEGIS-XSS-001"
