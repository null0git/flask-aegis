"""
flask_aegis.sanitize
~~~~~~~~~~~~~~~~~~~~~~

Sanitization functions, as a companion to *detection*. The rules in
``flask_aegis.rules`` answer "is this input dangerous?" and default to
BLOCK; these functions answer "how do I make this input safe to keep?"
for the fields where blocking isn't the right call — a rich-text bio, a
display name that just needs HTML stripped rather than rejected outright,
a value that will later hit a spreadsheet export.

**Design opinion, stated plainly:** sanitize on the backend, always;
sanitize on the frontend too, but only as a UX nicety, never as the
security boundary. A client can always send raw bytes straight to your
API with the JS layer skipped entirely — curl doesn't run your
JavaScript. So every function here has a Python implementation that is
the actual defense, and a mirrored vanilla-JS implementation
(``flask_aegis/static/aegis-sanitize.js``) that exists only to:

1. give instant feedback in a live preview / character-count UI, and
2. reduce round-trips that would otherwise bounce off the backend rule
   and come back as a SANITIZE/BLOCK response.

The two implementations are kept behavior-equivalent on purpose (see
``tests/test_sanitize_parity.py``) so "what the user sees in the preview"
matches "what actually gets stored" — a mismatch between the two is
worse than having no client-side sanitization at all, because it trains
users to trust a preview that lied to them.

If you only have time to wire up one side, wire up the backend. The
frontend module is an enhancement, not a requirement.
"""
from __future__ import annotations

import html
import re
import unicodedata
from typing import Iterable, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# HTML / XSS
# ---------------------------------------------------------------------------

_DEFAULT_ALLOWED_TAGS = {
    "b", "i", "em", "strong", "u", "p", "br", "ul", "ol", "li",
    "a", "blockquote", "code", "pre", "span",
}
_DEFAULT_ALLOWED_ATTRS = {
    "a": {"href", "title", "rel"},
    "span": {"class"},
}
_SAFE_URL_SCHEMES = {"http", "https", "mailto"}

_TAG_PATTERN = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)((?:\s+[^<>]*)?)\s*(/?)>")
_ATTR_PATTERN = re.compile(
    r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"|'
    r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*'([^']*)'"
)
_SCRIPT_STYLE_PATTERN = re.compile(
    r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL
)
_COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL)


def escape_html(value: str) -> str:
    """Escape every HTML-significant character. Use this for fields that
    should never contain markup at all -- the equivalent of Jinja's
    autoescaping, exposed as a callable for use outside template
    rendering (e.g. before writing to a non-HTML sink that later gets
    embedded in HTML, such as a JSON field consumed by client-side
    templating)."""
    return html.escape(value, quote=True)


def sanitize_html(
    value: str,
    allowed_tags: Optional[Iterable[str]] = None,
    allowed_attrs: Optional[dict] = None,
) -> str:
    """Strip everything except an allowlist of tags/attributes, rather
    than rejecting the input outright. Intended for fields that
    legitimately need light formatting (a comment body, a bio) where
    ``escape_html`` would be too aggressive but raw HTML is unsafe.

    This is a small, dependency-free allowlist sanitizer suitable for
    basic formatting tags. For anything beyond that (embedded media,
    complex attributes, style attributes), use a dedicated library like
    ``bleach`` instead -- this function intentionally does not try to be
    a full HTML sanitizer.

    Unknown/disallowed tags are removed but their *text content* is kept
    (``<script>alert(1)</script>`` -> '', since script content is data
    for the browser, not display text; ``<b>hi</b>`` stays as ``<b>hi</b>``;
    ``<div>hi</div>`` becomes ``hi``).
    """
    tags = set(allowed_tags) if allowed_tags is not None else _DEFAULT_ALLOWED_TAGS
    attrs = allowed_attrs if allowed_attrs is not None else _DEFAULT_ALLOWED_ATTRS

    # Script/style content is removed wholesale (content included), since
    # it is never meant to be displayed text.
    value = _SCRIPT_STYLE_PATTERN.sub("", value)
    value = _COMMENT_PATTERN.sub("", value)

    def _replace_tag(match: re.Match) -> str:
        closing, tag_name, attr_str, self_closing = match.groups()
        tag_lower = tag_name.lower()
        if tag_lower not in tags:
            return ""  # drop the tag, keep surrounding text

        if closing:
            return f"</{tag_lower}>"

        kept_attrs = []
        allowed_for_tag = attrs.get(tag_lower, set())
        for m in _ATTR_PATTERN.finditer(attr_str or ""):
            name = (m.group(1) or m.group(3) or "").lower()
            val = m.group(2) if m.group(1) else m.group(4)
            if name not in allowed_for_tag:
                continue
            if name == "href" and not _is_safe_url(val):
                continue
            kept_attrs.append(f'{name}="{html.escape(val, quote=True)}"')

        attr_out = (" " + " ".join(kept_attrs)) if kept_attrs else ""
        return f"<{tag_lower}{attr_out}{'/' if self_closing else ''}>"

    return _TAG_PATTERN.sub(_replace_tag, value)


def _is_safe_url(url: str) -> bool:
    url = url.strip()
    if url.startswith(("#", "/")):
        return True
    parsed = urlparse(url)
    return parsed.scheme.lower() in _SAFE_URL_SCHEMES if parsed.scheme else True


# ---------------------------------------------------------------------------
# General text
# ---------------------------------------------------------------------------

_CONTROL_CHAR_PATTERN = re.compile(
    "[" + "".join(chr(c) for c in range(0x00, 0x20) if c not in (0x09, 0x0A, 0x0D)) + "\x7f]"
)


def strip_control_chars(value: str) -> str:
    """Remove non-printable control characters (except tab/newline/CR),
    including the ones commonly used to smuggle payloads past naive
    filters or corrupt log output."""
    return _CONTROL_CHAR_PATTERN.sub("", value)


def normalize_whitespace(value: str) -> str:
    """Collapse runs of whitespace to a single space and strip the ends.
    Useful before length checks or comparisons, so 'a   b' and 'a b'
    aren't treated as different inputs by downstream validation."""
    return re.sub(r"\s+", " ", value).strip()


def normalize_unicode(value: str, form: str = "NFKC") -> str:
    """Apply Unicode normalization. Defends against homograph-style
    bypasses where visually-identical characters from different Unicode
    blocks are used to evade a string-based blocklist (e.g. a fullwidth
    or Cyrillic look-alike character in place of an ASCII one)."""
    return unicodedata.normalize(form, value)


# ---------------------------------------------------------------------------
# Filenames / paths
# ---------------------------------------------------------------------------

_FILENAME_UNSAFE_PATTERN = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(value: str, replacement: str = "_") -> str:
    """Replace characters that are unsafe in filenames across common
    filesystems (Windows reserved characters, path separators, control
    characters) with ``replacement``. Does not itself prevent path
    traversal on its own -- pair with
    ``flask_aegis.rules.traversal.safe_join_root`` when writing to disk,
    and with ``flask_aegis.upload.validate_upload`` for full upload
    validation (extension allowlist, double-extension detection)."""
    cleaned = _FILENAME_UNSAFE_PATTERN.sub(replacement, value)
    cleaned = cleaned.strip(". ")
    return cleaned or "unnamed"


# ---------------------------------------------------------------------------
# Identifiers (for building dynamic SQL column/table names, etc.)
# ---------------------------------------------------------------------------

_IDENTIFIER_PATTERN = re.compile(r"[^A-Za-z0-9_]")


def sanitize_identifier(value: str) -> str:
    """Reduce a string to a safe SQL/programming identifier: letters,
    digits, and underscores only, never starting with a digit. Intended
    for the narrow, legitimate case of building a dynamic column/table
    name from a constrained input (e.g. a sort-by field) -- this is
    *not* a substitute for parameterized queries on values; identifiers
    can't be parameterized by the DB driver, which is exactly why this
    function exists. Prefer validating against a fixed allowlist of real
    column names over this function wherever possible."""
    cleaned = _IDENTIFIER_PATTERN.sub("", value)
    if cleaned and cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned or "_"


# ---------------------------------------------------------------------------
# CSV / spreadsheet formula injection
# ---------------------------------------------------------------------------

_FORMULA_PREFIXES = ("=", "+", "-", "@")


def sanitize_csv_field(value: str) -> str:
    """Neutralize spreadsheet formula injection by prefixing a leading
    apostrophe when the value starts with a formula-triggering character
    (=, +, -, @). Spreadsheet applications display the apostrophe-quoted
    value as plain text instead of evaluating it as a formula."""
    stripped = value.lstrip()
    if stripped.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------


def sanitize_url(value: str, allowed_schemes: Iterable[str] = ("http", "https")) -> Optional[str]:
    """Return ``value`` unchanged if it parses as a URL with an allowed
    scheme, otherwise ``None``. This is a *format* check, not an SSRF
    check -- a URL can pass this and still point at an internal address.
    Use ``flask_aegis.ssrf.SSRFGuard`` for that before making an outbound
    request with the result."""
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {s.lower() for s in allowed_schemes}:
        return None
    if not parsed.netloc:
        return None
    return value
