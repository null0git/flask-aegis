"""
tests/fuzz/fuzz_rules.py
~~~~~~~~~~~~~~~~~~~~~~~~~~

Fuzzes every registered detection rule with randomly generated and
adversarially-mutated strings, asserting the invariant:

    A rule.check() call must never raise anything other than
    flask_aegis.exceptions.RuleError. Malformed/adversarial attacker
    input is a *finding*, not a Python exception.

This is a dependency-free harness (stdlib `random` only) so it runs
anywhere, including environments without `hypothesis` installed. For
idiomatic property-based tests once you have `hypothesis` available
(`pip install flask-aegis[dev]`), see tests/property/.

Run directly:
    python tests/fuzz/fuzz_rules.py [iterations] [seed]

Or via pytest (a thin wrapper test lives in tests/test_fuzz_smoke.py so
CI picks this up without needing a separate invocation).
"""
from __future__ import annotations

import random
import string
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from flask_aegis.context import RequestContext
from flask_aegis.exceptions import RuleError
from flask_aegis.rules import default_registry

# Seed corpus: fragments known to be interesting for these rule classes,
# recombined and mutated below rather than used verbatim -- the goal is
# to stress the regex engines and the field-option lookups, not just to
# replay known-good detections.
_SEED_FRAGMENTS = [
    "<script>", "</script>", "javascript:", "onerror=", "{{", "}}", "${",
    "#{", "<%=", "%>", "' OR '1'='1", "UNION SELECT", "--", "/*", "*/",
    "; DROP TABLE", "$(", "`", "&&", "||", "../", "..\\", "%2e%2e%2f",
    "(|(", "*)(", "\r\n", "Set-Cookie:", "=cmd|", "\x00", "\x1f", "\uFEFF",
    "𝕏𝕊𝕊", "＜script＞", "%00", "%0d%0a",
    "$ne", "$where", "$gt", "//evil.com", "/\\evil.com", "http://a@b.com",
    "__proto__", "constructor.prototype", "O:8:\"x\":1:{", "rO0AB",
    "${T(java.lang.Runtime).getRuntime()", "@java.lang.Runtime@",
    "c__main__\n", "\x80\x04", "169.254.169.254", "file://",
    "is_admin", "role", "(a+)+", "(a|a)+", "%n%n%n", "\\write18",
    "<!--#exec", "eyJhbGciOiJub25lIn0", "\u0430pple", "<!ENTITY",
]

_XML_SEED_FRAGMENTS = [
    "<!DOCTYPE", "<!ENTITY", "SYSTEM", "PUBLIC", "%xxe;", "<?xml", "<foo>",
    "file://", "http://", "]>", "<!--", "-->",
]
_RANDOM_CHARS = string.printable + "".join(chr(c) for c in range(0x80, 0x400, 7))


def _random_string(rng: random.Random, max_len: int = 200) -> str:
    """Either a pure-random string, or a recombination of seed fragments
    with random junk interspersed -- adversarial-ish without being a
    replay of fixed test cases."""
    if rng.random() < 0.5:
        length = rng.randint(0, max_len)
        return "".join(rng.choice(_RANDOM_CHARS) for _ in range(length))

    parts = []
    for _ in range(rng.randint(0, 6)):
        if rng.random() < 0.6:
            parts.append(rng.choice(_SEED_FRAGMENTS))
        else:
            parts.append("".join(rng.choice(_RANDOM_CHARS) for _ in range(rng.randint(0, 20))))
    return "".join(parts)


def fuzz_rules(iterations: int = 5000, seed: int = 1234) -> int:
    """Returns the number of check() calls made. Raises AssertionError
    (via a normal `assert`) on any rule that crashes with something other
    than RuleError -- that's the bug this harness exists to catch."""
    rng = random.Random(seed)
    registry = default_registry()
    rules = registry.all()
    field_names = ["username", "bio", "comment", "q", "id", "file", "uid", "amount", "redirect"]

    calls = 0
    for i in range(iterations):
        text_values = {
            rng.choice(field_names): _random_string(rng)
            for _ in range(rng.randint(1, 3))
        }
        # Occasionally attach random field options, since option lookups
        # are also part of the surface a malformed/unexpected config
        # could crash.
        field_options = {}
        if rng.random() < 0.3:
            for fname in text_values:
                field_options[fname] = {
                    rng.choice(["xss", "sqli", "ssti", "cmdi", "ldap", "xpath",
                                "header_injection", "csv_injection", "html",
                                "nosqli", "open_redirect", "hpp",
                                "deserialization", "ssrf_field", "proto_pollution",
                                "el_injection", "mass_assignment", "redos",
                                "jwt_weak", "homograph", "xml_bomb",
                                "ssi_injection", "latex_injection", "format_string"]):
                        rng.choice([True, False, None])
                }

        # raw_body: mostly plain random text, occasionally recombined
        # from XML-ish fragments so the XXE rule's regex path (which
        # only runs when raw_body is non-empty) actually gets exercised
        # rather than always short-circuiting via applies_to().
        raw_body = ""
        if rng.random() < 0.4:
            if rng.random() < 0.6:
                raw_body = "".join(
                    rng.choice(_XML_SEED_FRAGMENTS + [_random_string(rng, max_len=15)])
                    for _ in range(rng.randint(1, 8))
                )
            else:
                raw_body = _random_string(rng, max_len=100)

        # duplicate_params: occasionally simulate HTTP Parameter
        # Pollution input so the HPP rule's actual matching logic runs,
        # not just its applies_to() gate.
        duplicate_params = {}
        if rng.random() < 0.3:
            for fname in rng.sample(field_names, k=rng.randint(1, 2)):
                duplicate_params[fname] = [
                    _random_string(rng, max_len=10) for _ in range(rng.randint(2, 4))
                ]

        # Occasionally set an Authorization header (sometimes JWT-shaped,
        # sometimes not) so the JWT rule's Authorization-header path gets
        # exercised, not just its query/form-field path.
        headers = {}
        if rng.random() < 0.3:
            if rng.random() < 0.5:
                headers["Authorization"] = "Bearer " + _random_string(rng, max_len=60)
            else:
                headers["Authorization"] = "Bearer " + ".".join(
                    _random_string(rng, max_len=20) for _ in range(rng.randint(1, 3))
                )

        ctx = RequestContext(
            method=rng.choice(["GET", "POST", "PUT"]),
            path="/fuzz/" + _random_string(rng, max_len=30),
            remote_addr="127.0.0.1",
            text_values=text_values,
            path_segments=[_random_string(rng, max_len=20) for _ in range(rng.randint(0, 3))],
            raw_body=raw_body,
            duplicate_params=duplicate_params,
            headers=headers,
            field_options_lookup=field_options,
        )

        for rule in rules:
            calls += 1
            try:
                if not rule.applies_to(ctx):
                    continue
                rule.check(ctx)
            except RuleError:
                pass  # explicitly allowed -- a genuine internal rule error
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(
                    f"[iteration {i}] {rule.meta.rule_id} raised "
                    f"{type(exc).__name__}: {exc}\n"
                    f"text_values={text_values!r} field_options={field_options!r}"
                ) from exc

    return calls


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    s = int(sys.argv[2]) if len(sys.argv) > 2 else 1234
    total = fuzz_rules(iterations=n, seed=s)
    print(f"fuzz_rules: {n} iterations, {total} rule.check() calls, seed={s} -- no crashes")
