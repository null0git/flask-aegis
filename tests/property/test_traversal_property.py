"""
tests/property/test_traversal_property.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Idiomatic hypothesis property test for the invariant also checked by the
dependency-free harness in tests/fuzz/fuzz_traversal.py:

    A normalized path must never escape its configured root.

Requires the [dev] extra: `pip install flask-aegis[dev]`. Skipped
automatically if hypothesis isn't installed, so it doesn't block the
core suite in environments without it -- see tests/fuzz/ for a
zero-dependency equivalent that always runs.
"""
import os
import tempfile

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

from flask_aegis.rules.traversal import safe_join_root  # noqa: E402

_path_component = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="./\\%.-_ ",
    ),
    max_size=20,
)
_path_list = st.lists(_path_component, min_size=1, max_size=6)


@pytest.fixture(scope="module")
def root_dir():
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "safe_root")
        os.makedirs(root)
        yield root


@given(components=_path_list)
@settings(max_examples=500, deadline=None)
def test_safe_join_root_never_escapes(root_dir, components):
    result = safe_join_root(root_dir, *components)
    if result is None:
        return  # rejected -- invariant trivially holds
    root_abs = os.path.abspath(root_dir)
    result_abs = os.path.abspath(result)
    assert os.path.commonpath([root_abs, result_abs]) == root_abs


@given(components=_path_list)
@settings(max_examples=200, deadline=None)
def test_safe_join_root_never_raises(root_dir, components):
    # Malformed input is a None return, never an exception.
    safe_join_root(root_dir, *components)
