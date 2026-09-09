from flask_aegis.decisions import Decision, DecisionEngine, Finding


def _finding(decision):
    return Finding(rule_id="TEST-001", decision=decision, message="test")


def test_no_findings_allows():
    engine = DecisionEngine(mode="enforce")
    verdict = engine.resolve([])
    assert verdict.decision is Decision.ALLOW


def test_enforce_mode_uses_max_decision():
    engine = DecisionEngine(mode="enforce")
    verdict = engine.resolve([_finding(Decision.LOG), _finding(Decision.BLOCK)])
    assert verdict.decision is Decision.BLOCK


def test_monitor_mode_never_blocks():
    engine = DecisionEngine(mode="monitor")
    verdict = engine.resolve([_finding(Decision.BLOCK)])
    assert verdict.decision is Decision.LOG
    assert not verdict.blocked


def test_adaptive_mode_escalates_on_high_risk():
    engine = DecisionEngine(mode="adaptive")
    verdict = engine.resolve([_finding(Decision.LOG)], risk_score=95)
    assert verdict.decision is Decision.CHALLENGE


def test_adaptive_mode_leaves_low_risk_alone():
    engine = DecisionEngine(mode="adaptive")
    verdict = engine.resolve([_finding(Decision.LOG)], risk_score=10)
    assert verdict.decision is Decision.LOG


def test_invalid_mode_rejected():
    import pytest
    with pytest.raises(ValueError):
        DecisionEngine(mode="not-a-mode")
