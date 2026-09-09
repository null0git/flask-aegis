"""
tests/test_fuzz_smoke.py
~~~~~~~~~~~~~~~~~~~~~~~~~~

Thin pytest wrapper around the dependency-free fuzz harnesses in
tests/fuzz/, so `pytest` picks them up without a separate invocation.
Iteration counts here are kept modest for fast CI runs; run the scripts
directly with a higher count for deeper fuzzing:

    python tests/fuzz/fuzz_rules.py 50000
    python tests/fuzz/fuzz_traversal.py 20000
    python tests/fuzz/fuzz_policy.py 5000
"""
from tests.fuzz.fuzz_policy import fuzz_policy
from tests.fuzz.fuzz_rules import fuzz_rules
from tests.fuzz.fuzz_traversal import fuzz_traversal


def test_fuzz_rules_no_crashes():
    assert fuzz_rules(iterations=1000, seed=1234) > 0


def test_fuzz_rules_no_crashes_alt_seed():
    assert fuzz_rules(iterations=1000, seed=9999) > 0


def test_fuzz_traversal_invariant_holds():
    assert fuzz_traversal(iterations=1000, seed=1234) > 0


def test_fuzz_policy_determinism_holds():
    assert fuzz_policy(iterations=200, seed=1234) > 0
