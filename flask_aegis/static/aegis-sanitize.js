/*!
 * Flask-Aegis client-side sanitization module.
 * Mirrors flask_aegis/sanitize.py -- kept behavior-equivalent on purpose
 * (see tests/test_sanitize_parity.py) so a live preview never shows the
 * user something different from what the backend will actually store.
 *
 * IMPORTANT: this module is a UX convenience, not a security boundary.
 * Anything can call your API directly with the JS layer skipped
 * entirely (curl, a script, a modified client) -- the Python functions
 * in flask_aegis.sanitize are the actual defense. Use this module to:
 *   1. give instant feedback in a live preview / character-count UI, and
 *   2. reduce round-trips that would otherwise bounce off the backend
 *      SANITIZE/BLOCK response.
 * Never skip server-side sanitization because this ran on the client.
 *
 * Usage (plain <script> tag):
 *   <script src="{{ url_for('aegis_static.static', filename='aegis-sanitize.js') }}"></script>
 *   <script>
 *     const clean = AegisSanitize.sanitizeHtml(userInput);
 *   </script>
 *
 * Usage (ES module):
 *   import * as AegisSanitize from './aegis-sanitize.js';
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.AegisSanitize = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // -------------------------------------------------------------------
  // HTML / XSS
  // -------------------------------------------------------------------

  var DEFAULT_ALLOWED_TAGS = [
    "b", "i", "em", "strong", "u", "p", "br", "ul", "ol", "li",
    "a", "blockquote", "code", "pre", "span",
  ];
  var DEFAULT_ALLOWED_ATTRS = {
    a: ["href", "title", "rel"],
    span: ["class"],
  };
  var SAFE_URL_SCHEMES = ["http", "https", "mailto"];

  var HTML_ESCAPE_MAP = {
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;",
  };

  /** Escape every HTML-significant character. Use for fields that should
   * never contain markup at all. */
  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (c) {
      return HTML_ESCAPE_MAP[c];
    });
  }

  function isSafeUrl(url) {
    url = (url || "").trim();
    if (url.charAt(0) === "#" || url.charAt(0) === "/") return true;
    var match = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(url);
    if (!match) return true; // no scheme -- treated as a relative URL
    return SAFE_URL_SCHEMES.indexOf(match[1].toLowerCase()) !== -1;
  }

  var TAG_PATTERN = /<(\/?)([a-zA-Z][a-zA-Z0-9]*)((?:\s+[^<>]*)?)\s*(\/?)>/g;
  var ATTR_PATTERN = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"|([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*'([^']*)'/g;
  var SCRIPT_STYLE_PATTERN = /<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi;
  var COMMENT_PATTERN = /<!--[\s\S]*?-->/g;

  /**
   * Strip everything except an allowlist of tags/attributes, rather
   * than rejecting the input outright. Small, dependency-free allowlist
   * sanitizer -- for anything beyond basic formatting tags, use a
   * dedicated library (e.g. DOMPurify) on the client in addition to
   * this, and always rely on the backend as the source of truth.
   *
   * options: { allowedTags: string[], allowedAttrs: {tag: string[]} }
   */
  function sanitizeHtml(value, options) {
    options = options || {};
    var tags = options.allowedTags || DEFAULT_ALLOWED_TAGS;
    var attrs = options.allowedAttrs || DEFAULT_ALLOWED_ATTRS;
    var tagSet = {};
    for (var i = 0; i < tags.length; i++) tagSet[tags[i].toLowerCase()] = true;

    value = String(value).replace(SCRIPT_STYLE_PATTERN, "");
    value = value.replace(COMMENT_PATTERN, "");

    return value.replace(TAG_PATTERN, function (match, closing, tagName, attrStr, selfClosing) {
      var tagLower = tagName.toLowerCase();
      if (!tagSet[tagLower]) return "";

      if (closing) return "</" + tagLower + ">";

      var keptAttrs = [];
      var allowedForTag = attrs[tagLower] || [];
      var attrMatch;
      ATTR_PATTERN.lastIndex = 0;
      while ((attrMatch = ATTR_PATTERN.exec(attrStr || "")) !== null) {
        var name = (attrMatch[1] || attrMatch[3] || "").toLowerCase();
        var val = attrMatch[1] ? attrMatch[2] : attrMatch[4];
        if (allowedForTag.indexOf(name) === -1) continue;
        if (name === "href" && !isSafeUrl(val)) continue;
        keptAttrs.push(name + '="' + escapeHtml(val) + '"');
      }

      var attrOut = keptAttrs.length ? " " + keptAttrs.join(" ") : "";
      return "<" + tagLower + attrOut + (selfClosing ? "/" : "") + ">";
    });
  }

  // -------------------------------------------------------------------
  // General text
  // -------------------------------------------------------------------

  // eslint-disable-next-line no-control-regex
  var CONTROL_CHAR_PATTERN = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;

  /** Remove non-printable control characters (except tab/newline/CR). */
  function stripControlChars(value) {
    return String(value).replace(CONTROL_CHAR_PATTERN, "");
  }

  /** Collapse runs of whitespace to a single space and trim the ends. */
  function normalizeWhitespace(value) {
    return String(value).replace(/\s+/g, " ").trim();
  }

  /** Apply Unicode normalization (default NFKC) -- defends against
   * homograph-style bypasses using visually-identical characters. */
  function normalizeUnicode(value, form) {
    return String(value).normalize(form || "NFKC");
  }

  // -------------------------------------------------------------------
  // Filenames
  // -------------------------------------------------------------------

  // eslint-disable-next-line no-control-regex
  var FILENAME_UNSAFE_PATTERN = /[<>:"/\\|?*\x00-\x1f]/g;

  /** Replace filesystem-unsafe characters. Does not itself prevent path
   * traversal -- the backend still validates with safe_join_root. */
  function sanitizeFilename(value, replacement) {
    replacement = replacement || "_";
    var cleaned = String(value).replace(FILENAME_UNSAFE_PATTERN, replacement);
    cleaned = cleaned.replace(/^[.\s]+|[.\s]+$/g, "");
    return cleaned || "unnamed";
  }

  // -------------------------------------------------------------------
  // Identifiers
  // -------------------------------------------------------------------

  /** Reduce a string to a safe identifier: letters, digits, underscores
   * only. See the Python docstring for why this isn't a substitute for
   * parameterized queries. */
  function sanitizeIdentifier(value) {
    var cleaned = String(value).replace(/[^A-Za-z0-9_]/g, "");
    if (cleaned && /^[0-9]/.test(cleaned)) cleaned = "_" + cleaned;
    return cleaned || "_";
  }

  // -------------------------------------------------------------------
  // CSV / spreadsheet formula injection
  // -------------------------------------------------------------------

  var FORMULA_PREFIXES = ["=", "+", "-", "@"];

  /** Prefix a leading apostrophe when the value starts with a
   * formula-triggering character, so spreadsheet apps treat it as text. */
  function sanitizeCsvField(value) {
    var stripped = String(value).replace(/^\s+/, "");
    for (var i = 0; i < FORMULA_PREFIXES.length; i++) {
      if (stripped.indexOf(FORMULA_PREFIXES[i]) === 0) return "'" + value;
    }
    return value;
  }

  // -------------------------------------------------------------------
  // URLs
  // -------------------------------------------------------------------

  /** Return value unchanged if it parses as a URL with an allowed
   * scheme, otherwise null. Format check only -- not an SSRF check. */
  function sanitizeUrl(value, allowedSchemes) {
    allowedSchemes = (allowedSchemes || ["http", "https"]).map(function (s) {
      return s.toLowerCase();
    });
    value = String(value).trim();
    var match = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.+)$/.exec(value);
    if (!match || allowedSchemes.indexOf(match[1].toLowerCase()) === -1) return null;
    return value;
  }

  return {
    escapeHtml: escapeHtml,
    sanitizeHtml: sanitizeHtml,
    stripControlChars: stripControlChars,
    normalizeWhitespace: normalizeWhitespace,
    normalizeUnicode: normalizeUnicode,
    sanitizeFilename: sanitizeFilename,
    sanitizeIdentifier: sanitizeIdentifier,
    sanitizeCsvField: sanitizeCsvField,
    sanitizeUrl: sanitizeUrl,
  };
});
