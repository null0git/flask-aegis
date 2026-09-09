"""Standalone smoke test for Phase 2 features (no pytest dependency)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request
from flask_aegis import Aegis
from flask_aegis.context import RequestContext
from flask_aegis.rules.ssti import SSTIRule
from flask_aegis.rules.cmdi import CommandInjectionRule
from flask_aegis.rules.ldap_xpath import LDAPInjectionRule, XPathInjectionRule
from flask_aegis.rules.misc_injection import HeaderInjectionRule, CSVInjectionRule
from flask_aegis.ssrf import SSRFGuard, SSRFBlocked
from flask_aegis.upload import UploadPolicy, UploadRejected, validate_upload, safe_extract_zip
from flask_aegis.business import ActionPolicy, BusinessRules, ReplayGuard, BusinessRuleViolation

passed = 0
failed = 0

def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"PASS  {name}")
    else:
        failed += 1
        print(f"FAIL  {name}")

def ctx(**tv):
    return RequestContext(method="POST", path="/t", remote_addr="127.0.0.1", text_values=tv)

# --- SSTI ---
check("ssti rule detects jinja math probe", SSTIRule().check(ctx(name="{{7*7}}")) is not None)
check("ssti rule detects __class__ chain", SSTIRule().check(ctx(name="{{ ''.__class__.__mro__ }}")) is not None)
check("ssti rule ignores clean input", SSTIRule().check(ctx(name="John Smith")) is None)

# --- Command injection ---
check("cmdi rule detects semicolon+whoami", CommandInjectionRule().check(ctx(host="8.8.8.8; whoami")) is not None)
check("cmdi rule detects command substitution", CommandInjectionRule().check(ctx(host="$(id)")) is not None)
check("cmdi rule ignores clean input", CommandInjectionRule().check(ctx(host="8.8.8.8")) is None)

# --- LDAP / XPath ---
check("ldap rule detects filter injection", LDAPInjectionRule().check(ctx(uid="*)(uid=*))(|(uid=*")) is not None)
check("ldap rule ignores clean input", LDAPInjectionRule().check(ctx(uid="jsmith")) is None)
check("xpath rule detects boolean tautology", XPathInjectionRule().check(ctx(q="' or '1'='1")) is not None)
check("xpath rule ignores clean input", XPathInjectionRule().check(ctx(q="engineering")) is None)

# --- Header injection ---
hctx = ctx(redirect="/ok\r\nSet-Cookie: admin=true")
check("header injection rule detects CRLF+cookie", HeaderInjectionRule().check(hctx) is not None)
check("header injection rule ignores plain newline text",
      HeaderInjectionRule().check(ctx(bio="line one\nline two")) is None)

# --- CSV injection (opt-in) ---
csv_ctx = RequestContext(method="POST", path="/t", remote_addr="127.0.0.1",
                          text_values={"amount": "=cmd|'/c calc'!A1"},
                          field_options_lookup={"amount": {"csv_injection": True}})
check("csv injection rule flags formula prefix (opt-in field)",
      CSVInjectionRule().check(csv_ctx) is not None)
check("csv injection rule ignores field without opt-in",
      CSVInjectionRule().check(ctx(amount="=cmd|'/c calc'!A1")) is None)

# --- SSRF guard ---
guard = SSRFGuard()
try:
    guard.validate_url("http://169.254.169.254/latest/meta-data/")
    check("ssrf guard blocks link-local metadata IP", False)
except SSRFBlocked:
    check("ssrf guard blocks link-local metadata IP", True)

try:
    guard.validate_url("file:///etc/passwd")
    check("ssrf guard blocks file:// scheme", False)
except SSRFBlocked:
    check("ssrf guard blocks file:// scheme", True)

try:
    guard.validate_url("http://127.0.0.1:6379/")
    check("ssrf guard blocks loopback+denied port", False)
except SSRFBlocked:
    check("ssrf guard blocks loopback+denied port", True)

check("ssrf guard allows public https url", guard.validate_url("https://example.com/") == "https://example.com/")

# --- Upload policy ---
class FakeFile:
    def __init__(self, filename, content_type=None, content_length=None):
        self.filename = filename
        self.content_type = content_type
        self.content_length = content_length

policy = UploadPolicy(allowed_extensions={"png", "jpg", "pdf"})
try:
    validate_upload(FakeFile("invoice.pdf.exe"), policy)
    check("upload policy blocks double extension", False)
except UploadRejected:
    check("upload policy blocks double extension", True)

try:
    validate_upload(FakeFile("../../etc/passwd.png"), policy)
    check("upload policy blocks path separators in filename", False)
except UploadRejected:
    check("upload policy blocks path separators in filename", True)

try:
    validate_upload(FakeFile("report.exe"), policy)
    check("upload policy blocks disallowed extension", False)
except UploadRejected:
    check("upload policy blocks disallowed extension", True)

validate_upload(FakeFile("photo.png", content_length=1024), policy)
check("upload policy allows clean upload", True)

# --- Zip Slip protection ---
import tempfile, zipfile as zf_mod
with tempfile.TemporaryDirectory() as d:
    evil_zip = os.path.join(d, "evil.zip")
    with zf_mod.ZipFile(evil_zip, "w") as z:
        z.writestr("../../../../tmp/pwned.txt", "pwned")
    dest = os.path.join(d, "extract_dest")
    try:
        safe_extract_zip(evil_zip, dest)
        check("zip slip protection blocks malicious archive member", False)
    except UploadRejected:
        check("zip slip protection blocks malicious archive member", True)

    good_zip = os.path.join(d, "good.zip")
    with zf_mod.ZipFile(good_zip, "w") as z:
        z.writestr("readme.txt", "hello")
    dest2 = os.path.join(d, "extract_dest2")
    extracted = safe_extract_zip(good_zip, dest2)
    check("zip extraction succeeds for a clean archive", len(extracted) == 1 and os.path.exists(extracted[0]))

# --- Business rules: quota + replay, standalone ---
rules = BusinessRules()
rules.add(ActionPolicy(name="transfer", quota="2/minute", dedupe_header="Idempotency-Key"))

class FakeRequest:
    def __init__(self, headers=None, remote_addr="1.2.3.4"):
        self.headers = headers or {}
        self.remote_addr = remote_addr

rules.enforce("transfer", FakeRequest())
rules.enforce("transfer", FakeRequest())
try:
    rules.enforce("transfer", FakeRequest())
    check("business rules enforce quota", False)
except BusinessRuleViolation as e:
    check("business rules enforce quota", e.reason == "quota_exceeded")

rules2 = BusinessRules()
rules2.add(ActionPolicy(name="transfer", dedupe_header="Idempotency-Key"))
rules2.enforce("transfer", FakeRequest(headers={"Idempotency-Key": "abc123"}))
try:
    rules2.enforce("transfer", FakeRequest(headers={"Idempotency-Key": "abc123"}))
    check("business rules detect replay via idempotency key", False)
except BusinessRuleViolation as e:
    check("business rules detect replay via idempotency key", e.reason == "duplicate_request")

# --- Full Flask integration: protect_action decorator ---
app = Flask(__name__)
app.config.update(SECRET_KEY="test", TESTING=True)
aegis = Aegis(app, profile="standard")

@app.post("/transfer")
@aegis.protect_action("transfer2", quota="2/minute", dedupe_header="Idempotency-Key")
def transfer_view():
    return jsonify(ok=True)

client = app.test_client()
r1 = client.post("/transfer", headers={"Idempotency-Key": "k1"})
r2 = client.post("/transfer", headers={"Idempotency-Key": "k2"})
r3 = client.post("/transfer", headers={"Idempotency-Key": "k3"})
check("protect_action allows first two then quota-blocks third",
      r1.status_code == 200 and r2.status_code == 200 and r3.status_code == 429)

r4 = client.post("/register-dup-test") if False else None  # placeholder no-op

# Fresh app for replay test (avoid quota interference)
app2 = Flask(__name__)
app2.config.update(SECRET_KEY="test", TESTING=True)
aegis2 = Aegis(app2, profile="standard")

@app2.post("/transfer")
@aegis2.protect_action("transfer3", dedupe_header="Idempotency-Key")
def transfer_view2():
    return jsonify(ok=True)

client2 = app2.test_client()
r5 = client2.post("/transfer", headers={"Idempotency-Key": "dup-key"})
r6 = client2.post("/transfer", headers={"Idempotency-Key": "dup-key"})
check("protect_action returns 409 on replayed idempotency key",
      r5.status_code == 200 and r6.status_code == 409)

# --- New rules wired into the main pipeline via a policy ---
app3 = Flask(__name__)
app3.config.update(SECRET_KEY="test", TESTING=True)
aegis3 = Aegis(app3, profile="standard")
aegis3.add_policy("ssti_test", extends="public_form", rate_limit="100/minute", captcha=None)

@app3.post("/render")
@aegis3.protect("ssti_test")
def render_view():
    return jsonify(name=request.form.get("name"))

client3 = app3.test_client()
r7 = client3.post("/render", data={"name": "{{7*7}}"})
check("ssti payload blocked end-to-end via standard profile",
      r7.status_code == 403 and r7.get_json()["rule"] == "AEGIS-SSTI-001")

r8 = client3.post("/render", data={"name": "Alice"})
check("clean name passes end-to-end", r8.status_code == 200)

# --- Sanitization: unit-level ---
from flask_aegis.sanitize import (
    escape_html, sanitize_html, strip_control_chars, normalize_whitespace,
    normalize_unicode, sanitize_filename, sanitize_identifier,
    sanitize_csv_field, sanitize_url,
)

check("escape_html escapes all significant chars",
      escape_html("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;")
check("sanitize_html removes script tag and content",
      "script" not in sanitize_html("hi <script>alert(1)</script> there"))
check("sanitize_html keeps allowed tags",
      sanitize_html("<b>bold</b> <i>italic</i>") == "<b>bold</b> <i>italic</i>")
check("sanitize_html strips disallowed tag but keeps text",
      sanitize_html("<div>plain text</div>") == "plain text")
check("sanitize_html drops javascript: href",
      "javascript:" not in sanitize_html('<a href="javascript:alert(1)">click</a>'))
check("sanitize_html keeps safe href",
      'href="https://example.com"' in sanitize_html('<a href="https://example.com">click</a>'))
check("sanitize_html drops event handler attrs",
      "onclick" not in sanitize_html('<span onclick="evil()">x</span>'))
check("strip_control_chars removes null/bell, keeps newline",
      strip_control_chars("hello\x00\x07world\n") == "helloworld\n")
check("normalize_whitespace collapses runs",
      normalize_whitespace("  a   b\n\tc  ") == "a b c")
check("normalize_unicode NFKC collapses ligature",
      normalize_unicode("\uFB01le") == "file")
check("sanitize_filename strips path separators",
      "/" not in sanitize_filename("../../etc/passwd"))
check("sanitize_filename keeps normal names",
      sanitize_filename("my file (1).pdf") == "my file (1).pdf")
check("sanitize_identifier strips unsafe chars",
      sanitize_identifier("1; DROP TABLE users;--") == "_1DROPTABLEusers")
check("sanitize_csv_field prefixes formula",
      sanitize_csv_field("=cmd|'/c calc'!A1").startswith("'="))
check("sanitize_url accepts allowed scheme",
      sanitize_url("https://example.com/path") == "https://example.com/path")
check("sanitize_url rejects disallowed scheme",
      sanitize_url("javascript:alert(1)") is None)

# --- Sanitization: wired into the pipeline via SANITIZE decision ---
app4 = Flask(__name__)
app4.config.update(SECRET_KEY="test", TESTING=True)
aegis4 = Aegis(app4, profile="standard")
aegis4.add_policy("comments", extends="public_form", rate_limit="100/minute", captcha=None)
aegis4.field("comment", "body", xss_action="sanitize")

@app4.post("/comment")
@aegis4.protect("comments")
def comment_view():
    stored = aegis4.sanitized("body", default=request.form.get("body", ""))
    return jsonify(stored=stored)

client4 = app4.test_client()
r9 = client4.post("/comment", data={"body": "hi <script>alert(1)</script> there <b>bold</b>"})
check("sanitize field allows request through (200) instead of blocking",
      r9.status_code == 200)
check("sanitize field returns cleaned value via aegis.sanitized()",
      r9.get_json()["stored"] == "hi  there <b>bold</b>")

r10 = client4.post("/comment", data={"body": "just a normal comment"})
check("sanitize field leaves clean input untouched",
      r10.get_json()["stored"] == "just a normal comment")

# --- Frontend JS module served via static blueprint ---
r11 = client4.get("/_aegis/static/aegis-sanitize.js")
check("frontend sanitize module served at /_aegis/static/aegis-sanitize.js",
      r11.status_code == 200 and b"AegisSanitize" in r11.data)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
