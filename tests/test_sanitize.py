from flask_aegis.sanitize import (
    escape_html,
    normalize_unicode,
    normalize_whitespace,
    sanitize_csv_field,
    sanitize_filename,
    sanitize_html,
    sanitize_identifier,
    sanitize_url,
    strip_control_chars,
)


def test_escape_html_escapes_all_significant_chars():
    assert escape_html("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_sanitize_html_removes_script_tag_and_content():
    result = sanitize_html("hi <script>alert(1)</script> there")
    assert "script" not in result
    assert "alert" not in result


def test_sanitize_html_keeps_allowed_tags():
    result = sanitize_html("<b>bold</b> <i>italic</i>")
    assert result == "<b>bold</b> <i>italic</i>"


def test_sanitize_html_strips_disallowed_tag_keeps_text():
    result = sanitize_html("<div>plain text</div>")
    assert result == "plain text"


def test_sanitize_html_drops_javascript_href():
    result = sanitize_html('<a href="javascript:alert(1)">click</a>')
    assert "javascript:" not in result


def test_sanitize_html_keeps_safe_href():
    result = sanitize_html('<a href="https://example.com">click</a>')
    assert 'href="https://example.com"' in result


def test_sanitize_html_drops_event_handler_attrs():
    result = sanitize_html('<span onclick="evil()">x</span>')
    assert "onclick" not in result


def test_strip_control_chars_removes_null_and_bell():
    assert strip_control_chars("hello\x00\x07world") == "helloworld"


def test_strip_control_chars_keeps_newline_and_tab():
    assert strip_control_chars("a\nb\tc") == "a\nb\tc"


def test_normalize_whitespace_collapses_runs():
    assert normalize_whitespace("  a   b\n\tc  ") == "a b c"


def test_normalize_unicode_default_nfkc():
    assert normalize_unicode("\uFB01le") == "file"  # ligature 'fi' -> 'fi'


def test_sanitize_filename_replaces_path_separators():
    result = sanitize_filename("../../etc/passwd")
    assert "/" not in result


def test_sanitize_filename_keeps_normal_names():
    assert sanitize_filename("my file (1).pdf") == "my file (1).pdf"


def test_sanitize_filename_empty_fallback():
    assert sanitize_filename("...") == "unnamed"


def test_sanitize_identifier_strips_unsafe_chars():
    assert sanitize_identifier("1; DROP TABLE users;--") == "_1DROPTABLEusers"


def test_sanitize_identifier_keeps_valid_identifier():
    assert sanitize_identifier("user_name") == "user_name"


def test_sanitize_csv_field_prefixes_formula():
    result = sanitize_csv_field("=cmd|'/c calc'!A1")
    assert result.startswith("'=")


def test_sanitize_csv_field_leaves_plain_text():
    assert sanitize_csv_field("hello world") == "hello world"


def test_sanitize_url_accepts_allowed_scheme():
    assert sanitize_url("https://example.com/path") == "https://example.com/path"


def test_sanitize_url_rejects_disallowed_scheme():
    assert sanitize_url("javascript:alert(1)") is None


def test_sanitize_url_rejects_missing_netloc():
    assert sanitize_url("https://") is None
