"""
tests/test_sanitize_parity.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Verifies flask_aegis/sanitize.py and flask_aegis/static/aegis-sanitize.js
produce identical output for the same input. This is the guarantee that
makes the frontend module trustworthy as a UX layer: what a live preview
shows the user must match what the backend will actually store, or the
preview is actively misleading.

Requires Node.js on the PATH (skipped automatically if unavailable --
this is a cross-language contract test, not a core unit test, so its
absence shouldn't block `pytest` in an environment without Node).
"""
import json
import shutil
import subprocess

import pytest

from flask_aegis import sanitize

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="Node.js not available for JS parity check"
)

_JS_PATH = "./flask_aegis/static/aegis-sanitize.js"

# (python_function, js_function_name, [inputs...])
_CASES = [
    (sanitize.escape_html, "escapeHtml", ["<script>alert(1)</script>", "plain text", ""]),
    (sanitize.sanitize_html, "sanitizeHtml", [
        "hi <script>alert(1)</script> there",
        "<b>bold</b> <i>italic</i> <div>stripped div</div>",
        '<a href="javascript:alert(1)">click</a>',
        '<a href="https://example.com">click</a>',
        '<span onclick="evil()">x</span>',
        "no markup here",
    ]),
    (sanitize.strip_control_chars, "stripControlChars", ["hello\x00\x07world\n", "clean"]),
    (sanitize.normalize_whitespace, "normalizeWhitespace", ["  a   b\n\tc  ", "already normal"]),
    (sanitize.sanitize_filename, "sanitizeFilename", ["../../etc/passwd", "my file (1).pdf", "con.txt"]),
    (sanitize.sanitize_identifier, "sanitizeIdentifier", ["1; DROP TABLE users;--", "user_name", "9lives"]),
    (sanitize.sanitize_csv_field, "sanitizeCsvField", ["=cmd|'/c calc'!A1", "+15551234567", "normal text"]),
    (sanitize.sanitize_url, "sanitizeUrl", ["https://example.com/path", "javascript:alert(1)", "not a url"]),
]


def _run_js(js_fn_name: str, inputs: list) -> list:
    script = f"""
    const AegisSanitize = require('{_JS_PATH}');
    const inputs = {json.dumps(inputs)};
    const out = inputs.map(v => AegisSanitize.{js_fn_name}(v));
    console.log(JSON.stringify(out));
    """
    result = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("py_fn,js_fn_name,inputs", _CASES, ids=[c[1] for c in _CASES])
def test_python_and_js_agree(py_fn, js_fn_name, inputs):
    python_results = [py_fn(v) for v in inputs]
    js_results = _run_js(js_fn_name, inputs)
    assert python_results == js_results, (
        f"{js_fn_name}: Python and JS sanitizers disagree.\n"
        f"inputs:  {inputs}\n"
        f"python:  {python_results}\n"
        f"js:      {js_results}"
    )
