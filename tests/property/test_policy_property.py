"""
tests/property/test_policy_property.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Idiomatic hypothesis property test for the invariant also checked by the
dependency-free harness in tests/fuzz/fuzz_policy.py:

    A policy resolver must always produce a deterministic effective
    policy.

Requires the [dev] extra: `pip install flask-aegis[dev]`. Skipped
automatically if hypothesis isn't installed -- see tests/fuzz/ for a
zero-dependency equivalent that always runs.
"""
import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

from flask_aegis.exceptions import ConfigurationError, PolicyConflictError  # noqa: E402
from flask_aegis.policy import Policy, PolicyEngine  # noqa: E402

_bool_field = st.sampled_from([
    "csrf", "xss", "sqli", "traversal", "ssti", "cmdi",
    "ldap", "xpath", "header_injection", "csv_injection",
])
_rate_spec = st.one_of(
    st.none(),
    st.sampled_from(["5/minute", "10/hour", "1/second", "not-a-rate", "abc/minute"]),
)


@st.composite
def _policy_kwargs(draw):
    fields = draw(st.lists(_bool_field, max_size=5, unique=True))
    kwargs = {f: draw(st.booleans()) for f in fields}
    if draw(st.booleans()):
        kwargs["rate_limit"] = draw(_rate_spec)
    return kwargs


@given(kwargs_list=st.lists(_policy_kwargs(), min_size=1, max_size=8))
@settings(max_examples=300, deadline=None)
def test_compiling_same_policy_twice_is_deterministic(kwargs_list):
    engine = PolicyEngine()
    names = [f"p{i}" for i in range(len(kwargs_list))]
    for i, (name, kwargs) in enumerate(zip(names, kwargs_list)):
        extends = names[i - 1] if i > 0 else None
        try:
            engine.add(Policy(name=name, extends=extends, **kwargs))
        except (ConfigurationError, PolicyConflictError):
            return  # malformed by construction -- not what this test targets

    target = names[-1]
    try:
        first = engine.compile(target)
        second = engine.compile(target)
    except (ConfigurationError, PolicyConflictError):
        return

    assert first == second


@given(cycle_len=st.integers(min_value=2, max_value=6))
@settings(max_examples=50, deadline=None)
def test_circular_inheritance_always_rejected(cycle_len):
    engine = PolicyEngine()
    names = [f"c{i}" for i in range(cycle_len)]
    for i, name in enumerate(names):
        engine.add(Policy(name=name, extends=names[i - 1]))

    with pytest.raises(PolicyConflictError):
        engine.compile(names[0])
