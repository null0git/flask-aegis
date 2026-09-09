import pytest

from flask_aegis.business import ActionPolicy, BusinessRules, BusinessRuleViolation


class FakeRequest:
    def __init__(self, headers=None, remote_addr="1.2.3.4"):
        self.headers = headers or {}
        self.remote_addr = remote_addr


def test_quota_enforced_after_limit():
    rules = BusinessRules()
    rules.add(ActionPolicy(name="transfer", quota="2/minute"))
    rules.enforce("transfer", FakeRequest())
    rules.enforce("transfer", FakeRequest())
    with pytest.raises(BusinessRuleViolation) as exc:
        rules.enforce("transfer", FakeRequest())
    assert exc.value.reason == "quota_exceeded"


def test_replay_detected_via_idempotency_header():
    rules = BusinessRules()
    rules.add(ActionPolicy(name="transfer", dedupe_header="Idempotency-Key"))
    rules.enforce("transfer", FakeRequest(headers={"Idempotency-Key": "abc"}))
    with pytest.raises(BusinessRuleViolation) as exc:
        rules.enforce("transfer", FakeRequest(headers={"Idempotency-Key": "abc"}))
    assert exc.value.reason == "duplicate_request"


def test_different_idempotency_keys_both_allowed():
    rules = BusinessRules()
    rules.add(ActionPolicy(name="transfer", dedupe_header="Idempotency-Key"))
    rules.enforce("transfer", FakeRequest(headers={"Idempotency-Key": "a"}))
    rules.enforce("transfer", FakeRequest(headers={"Idempotency-Key": "b"}))  # no raise


def test_unregistered_action_is_noop():
    rules = BusinessRules()
    rules.enforce("no-such-action", FakeRequest())  # no raise


def test_quota_scoped_per_identity():
    rules = BusinessRules()
    rules.add(ActionPolicy(name="transfer", quota="1/minute"))
    rules.enforce("transfer", FakeRequest(remote_addr="1.1.1.1"))
    rules.enforce("transfer", FakeRequest(remote_addr="2.2.2.2"))  # different identity, no raise
