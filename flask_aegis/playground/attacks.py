"""
flask_aegis.playground.attacks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Attack definitions for the interactive playground: one entry per
detection category, each with a human description, an example payload,
and a *contained* vulnerable sink demonstrating what happens to that
input in a real (if safety-bounded) application without Flask-Aegis in
front of it.

Containment choices mirror examples/vulnerable_app/app.py -- see that
module's docstring for the full rationale. Summary: SQLi runs against an
in-memory SQLite database seeded with fake data; traversal is confined
to a temp sandbox directory; command injection is simulated (never
calls a real shell); XXE parsing is simulated by extracting what an
unsafe parser *would* have fetched, rather than actually resolving
external entities; open redirect shows the target instead of issuing a
real redirect, since this is consumed by a fetch()-based UI, not a
browser navigation.
"""
from __future__ import annotations

import os
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Optional

from flask import render_template_string


@dataclass
class Attack:
    id: str
    name: str
    category: str
    """Matches a flask_aegis Policy field name (xss, sqli, ...)."""
    rule_id: str
    severity: str
    description: str
    mitigation: str
    example_payload: str
    field_name: str = "value"
    field_options: dict = field(default_factory=dict)
    """Extra aegis.field(...) options this attack's protected route
    needs beyond enabling its own category -- e.g. open_redirect and
    csv_injection require an explicit per-field opt-in on top of the
    category being enabled."""
    vulnerable_fn: Optional[Callable[[str], dict]] = None
    clean_example: str = "a normal value"


# ---------------------------------------------------------------------------
# Contained fixtures shared by a few of the vulnerable_fn implementations
# ---------------------------------------------------------------------------

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
_db.executemany(
    "INSERT INTO users (username, email) VALUES (?, ?)",
    [("alice", "alice@example.com"), ("bob", "bob@example.com")],
)
_db.commit()

_sandbox_dir = tempfile.mkdtemp(prefix="aegis-playground-")
_public_dir = os.path.join(_sandbox_dir, "public")
os.makedirs(_public_dir)
with open(os.path.join(_public_dir, "public.txt"), "w") as f:
    f.write("this file is meant to be readable\n")
with open(os.path.join(_sandbox_dir, "secret.txt"), "w") as f:
    f.write("this file should NOT be reachable via the file parameter\n")


def _cleanup_sandbox():
    shutil.rmtree(_sandbox_dir, ignore_errors=True)


import atexit
atexit.register(_cleanup_sandbox)


# ---------------------------------------------------------------------------
# Vulnerable sinks -- one per attack class
# ---------------------------------------------------------------------------

def _vuln_xss(value: str) -> dict:
    return {"output": f"<div>Hello, {value}!</div>", "explanation":
             "This HTML is returned to the browser unescaped -- if the "
             "payload contains a script tag it will execute."}


def _vuln_sqli(value: str) -> dict:
    query = f"SELECT id, username, email FROM users WHERE username = '{value}'"
    try:
        rows = _db.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        return {"output": f"SQL error: {exc}", "query": query}
    return {"output": rows, "query": query, "explanation":
             "The query was built by string concatenation -- an "
             "unexpected row count above means the filter was bypassed."}


def _vuln_traversal(value: str) -> dict:
    path = os.path.join(_public_dir, value or "public.txt")
    try:
        with open(path) as fh:
            return {"output": fh.read(), "path": path}
    except OSError as exc:
        return {"output": f"Error: {exc}", "path": path}


def _vuln_ssti(value: str) -> dict:
    try:
        rendered = render_template_string(value or "Hello, world!")
    except Exception as exc:  # noqa: BLE001 -- template errors are part of the demo
        rendered = f"Template error: {exc}"
    return {"output": rendered, "explanation":
             "Your input was evaluated as a Jinja template, not displayed "
             "as literal text -- {{7*7}} becoming 49 proves real "
             "server-side execution."}


def _vuln_cmdi(value: str) -> dict:
    # SIMULATED -- never actually calls a shell. See module docstring.
    simulated_command = f"ping -c 1 {value or 'example.com'}"
    return {"output": f"[simulated -- not executed] would run: {simulated_command}",
            "explanation": "In a real app using os.system()/subprocess with "
                            "shell=True, everything after the semicolon "
                            "would run as a separate command."}


def _vuln_ldap(value: str) -> dict:
    ldap_filter = f"(&(uid={value or 'jdoe'})(objectClass=person))"
    return {"output": ldap_filter, "explanation":
             "This is the LDAP filter your input would produce. A "
             "payload closing the uid clause early and adding its own "
             "OR-wildcard changes which directory entries match."}


def _vuln_xpath(value: str) -> dict:
    xpath_expr = f"//user[username='{value or 'jdoe'}']"
    return {"output": xpath_expr, "explanation":
             "This is the XPath expression your input would produce. A "
             "boolean tautology (' or '1'='1) makes the predicate match "
             "every node instead of just one user."}


def _vuln_header_injection(value: str) -> dict:
    header_block = f"HTTP/1.1 302 Found\r\nLocation: /welcome?msg={value}\r\n\r\n"
    return {"output": header_block, "explanation":
             "This is the raw header block your input would produce if "
             "interpolated into a response header. A CRLF sequence lets "
             "an attacker inject an entirely new header (e.g. Set-Cookie) "
             "or split the response."}


def _vuln_csv_injection(value: str) -> dict:
    csv_row = f"username,note\r\nexported_user,{value}\r\n"
    return {"output": csv_row, "explanation":
             "This is the CSV row your input would produce on export. A "
             "leading '=', '+', '-', or '@' is interpreted as a formula "
             "by Excel/Sheets/LibreOffice when the file is opened."}


def _vuln_nosqli(value: str) -> dict:
    import json
    try:
        parsed = json.loads(value)
        semantics = f"parsed as a MongoDB operator document: {parsed}"
    except (json.JSONDecodeError, TypeError):
        semantics = f"treated as a plain string match: {{'username': {value!r}}}"
    return {"output": semantics, "explanation":
             "If your input is passed straight into a MongoDB filter "
             "without validating it's a plain string, an operator "
             "document like {\"$ne\": null} changes the query's meaning "
             "entirely instead of matching literally."}


def _vuln_xxe(value: str) -> dict:
    match = re.search(r'SYSTEM\s+["\']([^"\']+)["\']', value or "")
    if match:
        target = match.group(1)
        return {"output": f"[simulated -- not resolved] an unsafe XML parser "
                           f"would fetch: {target}",
                "explanation": "A real vulnerable parser with external entity "
                                "resolution enabled would fetch this URI "
                                "(often file:// for local file disclosure, or "
                                "http:// for SSRF) and substitute the result "
                                "into the document."}
    return {"output": "No external entity reference found in this XML.",
            "explanation": "Try including a DOCTYPE with an ENTITY ... SYSTEM clause."}


def _vuln_open_redirect(value: str) -> dict:
    return {"output": f"[simulated -- no real redirect issued] the browser "
                       f"would navigate to: {value}",
            "explanation": "If this value is passed straight to redirect() "
                            "after a login/action, a protocol-relative or "
                            "credential-prefixed URL sends the user to an "
                            "attacker-controlled site that looks like it "
                            "came from a trusted link."}


def _vuln_hpp(value: str) -> dict:
    # `value` here is ignored -- HPP is demonstrated by the query string
    # itself containing the same key twice (see playground/__init__.py's
    # route, which reads request.args.getlist directly).
    return {"output": "See 'first_value' vs 'all_values' below.",
            "explanation": "Different parts of a stack can disagree about "
                            "which duplicate value to use -- this is the "
                            "inconsistency HPP attacks exploit."}


def _vuln_deserialization(value: str) -> dict:
    import base64
    detail = "no recognizable serialization marker found"
    if value.strip().startswith("c") and "\n" in value:
        detail = "Python pickle GLOBAL opcode -- would import and call an arbitrary module.class"
    elif value.strip().startswith('O:'):
        detail = "PHP serialized object notation -- would instantiate the named class with attacker-set properties"
    else:
        try:
            decoded = base64.b64decode(value.strip() + "=" * (-len(value.strip()) % 4))
            if decoded[:4] == b"\xac\xed\x00\x05":
                detail = "base64-decoded Java serialized object stream header"
        except Exception:
            pass
    return {"output": f"[simulated -- not deserialized] {detail}",
            "explanation": "A real app calling pickle.loads()/unserialize()/"
                            "readObject() on this value would execute "
                            "attacker-controlled code as a side effect of "
                            "reconstructing the object graph."}


def _vuln_ssrf_field(value: str) -> dict:
    return {"output": f"[simulated -- no real request made] your backend "
                       f"would attempt to fetch: {value}",
            "explanation": "If this value is passed to requests.get()/urlopen() "
                            "for a 'validate this webhook' or 'fetch this image' "
                            "feature, an internal/metadata address lets an "
                            "attacker read internal services or cloud "
                            "credentials your server can reach but the "
                            "internet can't."}


def _vuln_proto_pollution(value: str) -> dict:
    return {"output": f"[simulated] a vulnerable deep-merge would set: "
                       f"Object.prototype.{value.replace('__proto__.', '').replace('__proto__', 'polluted')} "
                       f"on EVERY object in the JS runtime",
            "explanation": "If this key is merged into an object by a "
                            "vulnerable recursive merge utility downstream "
                            "(a Node build step, a JS frontend), the "
                            "attacker sets a property on Object.prototype "
                            "itself -- affecting every other object in that "
                            "runtime, not just this one."}


def _vuln_el_injection(value: str) -> dict:
    return {"output": f"[simulated -- not evaluated] a Spring EL/OGNL "
                       f"evaluator would execute: {value}",
            "explanation": "If a downstream Java/Spring component in your "
                            "stack evaluates this as an expression (a "
                            "common pattern in template engines and some "
                            "validation frameworks), T(...) type access "
                            "reaches java.lang.Runtime and executes an "
                            "arbitrary OS command."}


def _vuln_mass_assignment(value: str) -> dict:
    return {"output": f"[simulated -- not applied] User(**request.json) would "
                       f"set attribute '{value}' directly on the model",
            "explanation": "If a handler builds a model from the raw request "
                            "body without an explicit allowlist of assignable "
                            "fields, submitting a privileged key like this "
                            "sets it on the new/updated record exactly as if "
                            "an admin had set it deliberately."}


def _vuln_redos(value: str) -> dict:
    import re, time
    try:
        compiled = re.compile(value)
        start = time.perf_counter()
        # A short adversarial string against a vulnerable pattern still
        # takes a noticeable, measurable amount of time even bounded --
        # capped so the playground itself never actually hangs.
        compiled.match("a" * 25 + "!")
        elapsed = (time.perf_counter() - start) * 1000
        return {"output": f"[bounded test -- 25-char input] match attempt took {elapsed:.2f}ms",
                "explanation": "A vulnerable pattern's matching time grows "
                                "exponentially with input length -- this test "
                                "uses a short, fixed string so the playground "
                                "itself can't actually hang, but a real "
                                "attacker would grow the input until a single "
                                "request ties up a worker indefinitely."}
    except re.error as exc:
        return {"output": f"Pattern did not compile: {exc}", "explanation": ""}


def _vuln_jwt_weak(value: str) -> dict:
    import base64, json
    try:
        header_b64 = value.split(".")[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {"output": "Not a parseable JWT header", "explanation": ""}
    return {"output": f"[simulated -- not verified] header claims alg={header.get('alg')!r}; "
                       f"a verifier that trusts this claim would skip signature "
                       f"checking entirely for 'none'",
            "explanation": "A JWT library that reads 'alg' from the token "
                            "itself to decide how to verify it (rather than "
                            "the caller hardcoding the expected algorithm) "
                            "accepts this token as valid with no signature "
                            "check at all."}


def _vuln_homograph(value: str) -> dict:
    scripts = set()
    for ch in value:
        if ch.isalpha():
            try:
                import unicodedata
                name = unicodedata.name(ch)
                if name.startswith("CYRILLIC"):
                    scripts.add("Cyrillic")
                elif name.startswith("GREEK"):
                    scripts.add("Greek")
                elif name.startswith("LATIN"):
                    scripts.add("Latin")
            except ValueError:
                pass
    return {"output": f"[simulated] scripts detected in this string: {sorted(scripts) or ['none']}",
            "explanation": "A domain or username mixing scripts like this "
                            "renders as visually identical to the trusted "
                            "brand it's impersonating in most fonts -- the "
                            "bytes are completely different from the real "
                            "domain even though a human reader can't tell."}


def _vuln_xml_bomb(value: str) -> dict:
    entity_count = value.count("<!ENTITY")
    return {"output": f"[simulated -- not parsed] a parser without expansion "
                       f"limits would recursively resolve {entity_count} "
                       f"internal entity definition(s)",
            "explanation": "Each entity referencing several already-defined "
                            "entities multiplies the expansion -- a few "
                            "kilobytes of XML with enough nesting expands to "
                            "gigabytes in memory when the parser resolves it, "
                            "a denial of service that needs no external "
                            "network access at all."}


def _vuln_ssi_injection(value: str) -> dict:
    return {"output": f"[simulated -- not executed] an SSI-enabled server "
                       f"would execute the directive in: {value}",
            "explanation": "Server-Side Includes directives "
                            "(<!--#exec cmd=\"...\"-->) run on the web server "
                            "itself when it serves the page -- if user input "
                            "reaches an SSI-processed response, this is "
                            "equivalent to command injection."}


def _vuln_latex_injection(value: str) -> dict:
    return {"output": f"[simulated -- not compiled] pdflatex would execute "
                       f"this as part of the document source: {value}",
            "explanation": "\\write18 enables arbitrary shell command "
                            "execution during LaTeX compilation if "
                            "shell-escape is enabled; \\input/\\include read "
                            "arbitrary files into the compiled document."}


def _vuln_format_string(value: str) -> dict:
    return {"output": f"[simulated -- not passed to printf] a native printf-family "
                       f"call using this as the format string would interpret: {value}",
            "explanation": "%n writes the number of bytes written so far to "
                            "a pointer argument -- if the attacker controls "
                            "the format string itself (not just a value "
                            "argument), this becomes an arbitrary memory "
                            "write primitive."}


ATTACKS = [
    Attack(
        id="xss", name="Cross-Site Scripting (XSS)", category="xss",
        rule_id="AEGIS-XSS-001",
        severity="high",
        description="Injecting script that executes in another user's browser.",
        mitigation="Escape output at render time; set a strict Content-Security-Policy.",
        example_payload="<script>alert('XSS')</script>",
        clean_example="Alice",
        vulnerable_fn=_vuln_xss,
    ),
    Attack(
        id="sqli", name="SQL Injection", category="sqli",
        rule_id="AEGIS-SQLI-001",
        severity="critical",
        description="Manipulating a database query by injecting SQL syntax into input.",
        mitigation="Use parameterized queries / an ORM -- never string-concatenated SQL.",
        example_payload="' OR '1'='1",
        clean_example="alice",
        vulnerable_fn=_vuln_sqli,
    ),
    Attack(
        id="traversal", name="Path Traversal", category="traversal",
        rule_id="AEGIS-TRAVERSAL-001",
        severity="high",
        description="Escaping an intended directory to read arbitrary files.",
        mitigation="Validate resolved paths stay within an allowed root (safe_join_root).",
        example_payload="../secret.txt",
        clean_example="public.txt",
        vulnerable_fn=_vuln_traversal,
    ),
    Attack(
        id="ssti", name="Server-Side Template Injection", category="ssti",
        rule_id="AEGIS-SSTI-001",
        severity="critical",
        description="Treating user input as template source instead of data.",
        mitigation="Never pass user input to render_template_string() as the template itself.",
        example_payload="{{7*7}}",
        clean_example="just plain text",
        vulnerable_fn=_vuln_ssti,
    ),
    Attack(
        id="cmdi", name="Command Injection", category="cmdi",
        rule_id="AEGIS-CMD-001",
        severity="critical",
        description="Injecting shell metacharacters to run additional OS commands.",
        mitigation="Use subprocess.run([...], shell=False) with an argument list.",
        example_payload="8.8.8.8; whoami",
        clean_example="8.8.8.8",
        vulnerable_fn=_vuln_cmdi,
    ),
    Attack(
        id="ldap", name="LDAP Injection", category="ldap",
        rule_id="AEGIS-LDAP-001",
        severity="high",
        description="Manipulating an LDAP filter's boolean logic via unescaped metacharacters.",
        mitigation="Escape filter metacharacters (e.g. ldap3.utils.conv.escape_filter_chars).",
        example_payload="*)(uid=*))(|(uid=*",
        clean_example="jdoe",
        vulnerable_fn=_vuln_ldap,
    ),
    Attack(
        id="xpath", name="XPath Injection", category="xpath",
        rule_id="AEGIS-XPATH-001",
        severity="high",
        description="Manipulating an XPath expression's predicate logic.",
        mitigation="Use parameterized XPath (e.g. lxml.etree.XPath with variables).",
        example_payload="' or '1'='1",
        clean_example="jdoe",
        vulnerable_fn=_vuln_xpath,
    ),
    Attack(
        id="header_injection", name="Header / Log Injection", category="header_injection",
        rule_id="AEGIS-HEADER-001",
        severity="high",
        description="Injecting CRLF sequences to split or forge HTTP headers or log lines.",
        mitigation="Never interpolate raw input into a header or log format string.",
        example_payload="ok\r\nSet-Cookie: admin=true",
        clean_example="ok",
        vulnerable_fn=_vuln_header_injection,
    ),
    Attack(
        id="csv_injection", name="CSV / Formula Injection", category="csv_injection",
        rule_id="AEGIS-CSV-001",
        severity="medium",
        description="A leading =, +, -, or @ is interpreted as a spreadsheet formula on export.",
        mitigation="Prefix an apostrophe on export (see flask_aegis.sanitize.sanitize_csv_field).",
        example_payload="=cmd|'/c calc'!A1",
        clean_example="normal note",
        field_options={"csv_injection": True},
        vulnerable_fn=_vuln_csv_injection,
    ),
    Attack(
        id="nosqli", name="NoSQL Injection", category="nosqli",
        rule_id="AEGIS-NOSQLI-001",
        severity="critical",
        description="Injecting MongoDB-style query operators where a plain string was expected.",
        mitigation="Validate that filter fields are the scalar type you expect before querying.",
        example_payload='{"$ne": null}',
        clean_example="alice",
        vulnerable_fn=_vuln_nosqli,
    ),
    Attack(
        id="xxe", name="XML External Entity (XXE)", category="xxe",
        rule_id="AEGIS-XXE-001",
        severity="critical",
        description="Declaring an external entity to read local files or trigger SSRF via XML.",
        mitigation="Disable DTD processing and external entity resolution (e.g. defusedxml).",
        example_payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        clean_example="<foo>bar</foo>",
        vulnerable_fn=_vuln_xxe,
    ),
    Attack(
        id="open_redirect", name="Open Redirect", category="open_redirect",
        rule_id="AEGIS-REDIRECT-001",
        severity="medium",
        description="A redirect target under attacker control sends users to a malicious site.",
        mitigation="Validate the redirect target against an explicit allowlist of hosts/paths.",
        example_payload="//evil.example.com",
        field_name="next",
        clean_example="/dashboard",
        field_options={"open_redirect": True},
        vulnerable_fn=_vuln_open_redirect,
    ),
    Attack(
        id="hpp", name="HTTP Parameter Pollution", category="hpp",
        rule_id="AEGIS-HPP-001",
        severity="medium",
        description="Submitting the same parameter twice with different values.",
        mitigation="Ensure every layer of your stack agrees on which duplicate value wins.",
        example_payload="user",  # actual pollution is added by the route itself
        clean_example="user",
        vulnerable_fn=_vuln_hpp,
    ),
    Attack(
        id="deserialization", name="Insecure Deserialization", category="deserialization",
        rule_id="AEGIS-DESERIAL-001",
        severity="critical",
        description="Deserializing attacker-controlled data executes code as a side effect.",
        mitigation="Never deserialize request data with pickle/unserialize()/readObject(); use JSON.",
        example_payload="c__main__\nsome_class\n",
        clean_example="just a normal comment",
        vulnerable_fn=_vuln_deserialization,
    ),
    Attack(
        id="ssrf_field", name="SSRF (Request Field)", category="ssrf_field",
        rule_id="AEGIS-SSRF-001",
        severity="critical",
        description="A URL field pointing at an internal/metadata address your server can reach.",
        mitigation="Validate outbound URLs with flask_aegis.ssrf.SSRFGuard before fetching.",
        example_payload="http://169.254.169.254/latest/meta-data/",
        field_name="webhook_url",
        clean_example="https://example.com/hook",
        field_options={"ssrf_field": True},
        vulnerable_fn=_vuln_ssrf_field,
    ),
    Attack(
        id="proto_pollution", name="Prototype Pollution", category="proto_pollution",
        rule_id="AEGIS-PROTO-001",
        severity="high",
        description="Injecting __proto__ to modify every object in a downstream JS runtime.",
        mitigation="Use a merge utility with prototype-pollution protection downstream.",
        example_payload="__proto__",
        clean_example="normal_key",
        vulnerable_fn=_vuln_proto_pollution,
    ),
    Attack(
        id="el_injection", name="Expression Language Injection", category="el_injection",
        rule_id="AEGIS-EL-001",
        severity="critical",
        description="Java/Spring EL or OGNL expressions reaching arbitrary code execution.",
        mitigation="Never evaluate an expression language against unvalidated input.",
        example_payload='${T(java.lang.Runtime).getRuntime().exec("id")}',
        clean_example="John Smith",
        vulnerable_fn=_vuln_el_injection,
    ),
    Attack(
        id="mass_assignment", name="Mass Assignment", category="mass_assignment",
        rule_id="AEGIS-MASSASSIGN-001",
        severity="high",
        description="A bulk-assign handler sets a privileged field an attacker included in the body.",
        mitigation="Use an explicit allowlist of assignable fields; never Model(**request.json).",
        example_payload="is_admin",
        clean_example="username",
        vulnerable_fn=_vuln_mass_assignment,
    ),
    Attack(
        id="redos", name="Regular Expression DoS (ReDoS)", category="redos",
        rule_id="AEGIS-REDOS-001",
        severity="high",
        description="A user-supplied regex with catastrophic backtracking hangs a worker.",
        mitigation="Compile user-supplied regexes with a timeout, or reject dangerous shapes.",
        example_payload="(a+)+$",
        field_name="value",
        clean_example="^[a-z]+$",
        field_options={"redos": True},
        vulnerable_fn=_vuln_redos,
    ),
    Attack(
        id="jwt_weak", name="JWT 'none' Algorithm", category="jwt_weak",
        rule_id="AEGIS-JWT-001",
        severity="critical",
        description="A JWT declaring alg=none bypasses signature verification entirely.",
        mitigation="Hardcode the expected algorithm when verifying; never trust the token's own alg claim.",
        example_payload="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ.",
        clean_example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig",
        vulnerable_fn=_vuln_jwt_weak,
    ),
    Attack(
        id="homograph", name="Homograph / Mixed-Script Spoofing", category="homograph",
        rule_id="AEGIS-HOMOGRAPH-001",
        severity="medium",
        description="Mixing Cyrillic/Greek look-alikes with Latin letters spoofs a trusted domain/name.",
        mitigation="Reject identity fields mixing scripts unless genuinely multilingual content is expected.",
        example_payload="\u0430pple.com",
        field_name="value",
        clean_example="apple.com",
        field_options={"homograph": True},
        vulnerable_fn=_vuln_homograph,
    ),
    Attack(
        id="xml_bomb", name="XML Entity Expansion Bomb", category="xml_bomb",
        rule_id="AEGIS-XMLBOMB-001",
        severity="high",
        description="Internal XML entities referencing each other expand exponentially in memory.",
        mitigation="Cap entity expansion or disable DTD processing entirely (defusedxml).",
        example_payload='<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
        clean_example="<foo>bar</foo>",
        vulnerable_fn=_vuln_xml_bomb,
    ),
    Attack(
        id="ssi_injection", name="Server-Side Includes (SSI) Injection", category="ssi_injection",
        rule_id="AEGIS-SSI-001",
        severity="high",
        description="An SSI directive in user input executes when an SSI-enabled server renders it.",
        mitigation="Disable SSI processing on any endpoint serving user-influenced content.",
        example_payload='<!--#exec cmd="whoami"-->',
        field_name="value",
        clean_example="a normal comment",
        field_options={"ssi_injection": True},
        vulnerable_fn=_vuln_ssi_injection,
    ),
    Attack(
        id="latex_injection", name="LaTeX Injection", category="latex_injection",
        rule_id="AEGIS-LATEX-001",
        severity="high",
        description="\\write18 and \\input reach shell execution and file access during PDF compilation.",
        mitigation="Compile with shell-escape disabled, in a sandboxed working directory.",
        example_payload="\\write18{cat /etc/passwd}",
        field_name="value",
        clean_example="John Smith",
        field_options={"latex_injection": True},
        vulnerable_fn=_vuln_latex_injection,
    ),
    Attack(
        id="format_string", name="Format String Injection", category="format_string",
        rule_id="AEGIS-FORMATSTR-001",
        severity="high",
        description="%n as a native printf-family format string becomes an arbitrary memory write.",
        mitigation="Never pass request-derived data as the format string argument to printf-family calls.",
        example_payload="%n%n%n%n",
        field_name="value",
        clean_example="John Smith",
        field_options={"format_string": True},
        vulnerable_fn=_vuln_format_string,
    ),
]

ATTACKS_BY_ID = {a.id: a for a in ATTACKS}
