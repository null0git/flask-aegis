from flask_aegis.context import RequestContext
from flask_aegis.rules.sqli import SQLiRule
from flask_aegis.rules.traversal import TraversalRule, safe_join_root
from flask_aegis.rules.xss import XSSRule


def _ctx(**text_values):
    return RequestContext(
        method="POST", path="/test", remote_addr="127.0.0.1",
        text_values=text_values,
    )


def test_xss_rule_detects_script_tag():
    rule = XSSRule()
    ctx = _ctx(comment="<script>alert(1)</script>")
    finding = rule.check(ctx)
    assert finding is not None
    assert finding.rule_id == "AEGIS-XSS-001"


def test_xss_rule_allows_html_exempt_field():
    rule = XSSRule()
    ctx = RequestContext(
        method="POST", path="/test", remote_addr="127.0.0.1",
        text_values={"bio": "<script>alert(1)</script>"},
        field_options_lookup={"bio": {"html": True}},
    )
    assert rule.check(ctx) is None


def test_xss_rule_ignores_clean_input():
    rule = XSSRule()
    ctx = _ctx(comment="just a normal comment")
    assert rule.check(ctx) is None


def test_sqli_rule_detects_union_select():
    rule = SQLiRule()
    ctx = _ctx(q="1 UNION SELECT username, password FROM users")
    finding = rule.check(ctx)
    assert finding is not None
    assert finding.rule_id == "AEGIS-SQLI-001"


def test_sqli_rule_detects_boolean_based():
    rule = SQLiRule()
    ctx = _ctx(id="1 OR 1=1")
    assert rule.check(ctx) is not None


def test_sqli_rule_ignores_clean_input():
    rule = SQLiRule()
    ctx = _ctx(id="42")
    assert rule.check(ctx) is None


def test_traversal_rule_detects_raw_sequence():
    rule = TraversalRule()
    ctx = _ctx(file="../../etc/passwd")
    assert rule.check(ctx) is not None


def test_traversal_rule_detects_encoded_sequence():
    rule = TraversalRule()
    ctx = _ctx(file="%2e%2e%2f%2e%2e%2fetc%2fpasswd")
    assert rule.check(ctx) is not None


def test_traversal_rule_ignores_clean_path():
    rule = TraversalRule()
    ctx = _ctx(file="reports/2026/summary.pdf")
    assert rule.check(ctx) is None


def test_safe_join_root_blocks_escape(tmp_path):
    root = tmp_path / "uploads"
    root.mkdir()
    assert safe_join_root(str(root), "../../etc/passwd") is None


def test_safe_join_root_allows_valid_path(tmp_path):
    root = tmp_path / "uploads"
    root.mkdir()
    result = safe_join_root(str(root), "reports", "file.pdf")
    assert result is not None
    assert result.startswith(str(root))
