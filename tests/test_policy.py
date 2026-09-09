import pytest

from flask_aegis.exceptions import ConfigurationError, PolicyConflictError, PolicyNotFoundError
from flask_aegis.policy import Policy, PolicyEngine


def test_basic_resolution():
    engine = PolicyEngine()
    engine.add(Policy("public_form", csrf=True, xss=True, rate_limit="20/minute"))
    compiled = engine.compile("public_form")
    assert compiled.csrf is True
    assert compiled.xss is True
    assert compiled.rate_limit == "20/minute"
    assert compiled.sqli is False  # inherited from base defaults


def test_inheritance_override():
    engine = PolicyEngine()
    engine.add(Policy("public_form", csrf=True, xss=True, rate_limit="20/minute"))
    engine.add(Policy("registration", extends="public_form",
                       captcha="adaptive", risk_threshold=60))
    compiled = engine.compile("registration")
    assert compiled.csrf is True          # inherited
    assert compiled.captcha == "adaptive"  # overridden
    assert compiled.risk_threshold == 60


def test_circular_inheritance_detected():
    engine = PolicyEngine()
    engine.add(Policy("a", extends="b"))
    engine.add(Policy("b", extends="a"))
    with pytest.raises(PolicyConflictError):
        engine.compile("a")


def test_self_extends_rejected():
    engine = PolicyEngine()
    with pytest.raises(PolicyConflictError):
        engine.add(Policy("a", extends="a"))


def test_missing_policy_raises():
    engine = PolicyEngine()
    with pytest.raises(PolicyNotFoundError):
        engine.compile("does-not-exist")


def test_invalid_rate_limit_rejected():
    engine = PolicyEngine()
    engine.add(Policy("bad", rate_limit="not-a-rate"))
    with pytest.raises(ConfigurationError):
        engine.compile("bad")


def test_adaptive_captcha_requires_threshold():
    engine = PolicyEngine()
    engine.add(Policy("bad", captcha="adaptive", risk_threshold=None))
    with pytest.raises(ConfigurationError):
        engine.compile("bad")


def test_noop_policy_flagged():
    engine = PolicyEngine()
    engine.add(Policy("empty"))
    compiled = engine.compile("empty")
    assert compiled.is_noop is True


def test_compile_all_covers_every_policy():
    engine = PolicyEngine()
    engine.add(Policy("a", csrf=True))
    engine.add(Policy("b", extends="a", xss=True))
    compiled = engine.compile_all()
    assert set(compiled) == {"a", "b"}
    assert compiled["b"].csrf is True
    assert compiled["b"].xss is True
