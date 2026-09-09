from flask import Flask

from flask_aegis import Aegis
from flask_aegis.config_export import export_config


def test_export_contains_no_secret_key():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="super-secret-value")
    aegis = Aegis(app, profile="minimal")
    data = export_config(aegis)
    assert "super-secret-value" not in str(data)


def test_export_contains_no_captcha_secret():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test")
    aegis = Aegis(app, profile="minimal", captcha={
        "provider": "recaptcha", "site_key": "public-key", "secret_key": "private-secret",
    })
    data = export_config(aegis)
    assert "private-secret" not in str(data)
    assert data["captcha_provider"] == "recaptcha"


def test_export_includes_profile_mode_ruleset():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test")
    aegis = Aegis(app, profile="strict", mode="monitor")
    data = export_config(aegis)
    assert data["profile"] == "strict"
    assert data["mode"] == "monitor"
    assert data["ruleset"] == "latest"


def test_export_includes_every_compiled_policy():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test")
    aegis = Aegis(app, profile="standard")
    aegis.add_policy("custom", extends="standard", rate_limit="42/minute")
    data = export_config(aegis)
    assert "custom" in data["policies"]
    assert data["policies"]["custom"]["rate_limit"] == "42/minute"


def test_export_includes_all_rule_ids():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test")
    aegis = Aegis(app, profile="minimal")
    data = export_config(aegis)
    assert len(data["rule_ids"]) == 25
    assert "AEGIS-XSS-001" in data["rule_ids"]


def test_export_is_yaml_serializable():
    import yaml
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test")
    aegis = Aegis(app, profile="standard")
    data = export_config(aegis)
    text = yaml.safe_dump(data)
    reloaded = yaml.safe_load(text)
    assert reloaded["profile"] == "standard"
