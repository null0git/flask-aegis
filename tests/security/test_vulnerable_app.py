"""
tests/security/test_vulnerable_app.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Demonstrates, against the deliberately vulnerable routes in
examples/vulnerable_app/app.py, both:

  1. that the vulnerability is real (the /vuln/* route is actually
     exploitable, not just theoretically insecure), and
  2. that the identical code pattern behind @aegis.protect(...) blocks
     the same payload.

This is what "flask aegis audit" and the rule metadata claim to do,
demonstrated end-to-end rather than asserted in the abstract. If a rule
regresses, one of these tests fails on the /protected/ side while the
/vuln/ side continues to prove the underlying pattern is still
genuinely dangerous without Flask-Aegis in front of it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "examples", "vulnerable_app"))


@pytest.fixture(scope="module")
def vuln_client():
    import app as vuln_app  # the vulnerable_app module, imported once per test session
    vuln_app.app.config["TESTING"] = True
    return vuln_app.app.test_client()


class TestXSS:
    def test_unprotected_route_reflects_script_tag_unescaped(self, vuln_client):
        resp = vuln_client.get("/vuln/xss", query_string={"name": "<script>alert(1)</script>"})
        assert resp.status_code == 200
        assert "<script>alert(1)</script>" in resp.get_data(as_text=True)

    def test_protected_route_blocks_same_payload(self, vuln_client):
        resp = vuln_client.get("/protected/xss", query_string={"name": "<script>alert(1)</script>"})
        assert resp.status_code == 403
        assert resp.get_json()["rule"] == "AEGIS-XSS-001"

    def test_protected_route_allows_clean_input(self, vuln_client):
        resp = vuln_client.get("/protected/xss", query_string={"name": "Alice"})
        assert resp.status_code == 200


class TestSQLInjection:
    def test_unprotected_route_boolean_injection_dumps_all_rows(self, vuln_client):
        resp = vuln_client.get("/vuln/sqli", query_string={"username": "' OR '1'='1"})
        assert resp.status_code == 200
        rows = resp.get_json()["rows"]
        # The filter was supposed to match zero users named "' OR '1'='1" --
        # getting both seeded users back proves the injection worked.
        assert len(rows) == 2

    def test_protected_route_blocks_same_payload(self, vuln_client):
        resp = vuln_client.get("/protected/sqli", query_string={"username": "' OR '1'='1"})
        assert resp.status_code == 403
        assert resp.get_json()["rule"] == "AEGIS-SQLI-001"

    def test_protected_route_allows_clean_input(self, vuln_client):
        resp = vuln_client.get("/protected/sqli", query_string={"username": "alice"})
        assert resp.status_code == 200
        assert len(resp.get_json()["rows"]) == 1


class TestPathTraversal:
    def test_unprotected_route_reads_file_outside_public_dir(self, vuln_client):
        resp = vuln_client.get("/vuln/traversal", query_string={"file": "../secret.txt"})
        assert resp.status_code == 200
        assert "should NOT be reachable" in resp.get_json()["content"]

    def test_protected_route_blocks_same_payload(self, vuln_client):
        resp = vuln_client.get("/protected/traversal", query_string={"file": "../secret.txt"})
        assert resp.status_code == 403
        assert resp.get_json()["rule"] == "AEGIS-TRAVERSAL-001"

    def test_safe_join_root_blocks_it_independently_of_aegis(self, vuln_client):
        # The actually-correct fix (see /safe/traversal) rejects the
        # escape on its own, without any Aegis policy attached.
        resp = vuln_client.get("/safe/traversal", query_string={"file": "../secret.txt"})
        assert resp.status_code == 400

    def test_protected_route_allows_legitimate_file(self, vuln_client):
        resp = vuln_client.get("/protected/traversal", query_string={"file": "public.txt"})
        assert resp.status_code == 200


class TestSSTI:
    def test_unprotected_route_evaluates_arithmetic_expression(self, vuln_client):
        # {{7*7}} -> '49' proves the input was evaluated as a Jinja
        # template, not displayed as literal text.
        resp = vuln_client.get("/vuln/ssti", query_string={"template": "{{7*7}}"})
        assert resp.status_code == 200
        assert resp.get_data(as_text=True) == "49"

    def test_protected_route_blocks_same_payload(self, vuln_client):
        resp = vuln_client.get("/protected/ssti", query_string={"template": "{{7*7}}"})
        assert resp.status_code == 403
        assert resp.get_json()["rule"] == "AEGIS-SSTI-001"

    def test_protected_route_allows_plain_text(self, vuln_client):
        resp = vuln_client.get("/protected/ssti", query_string={"template": "just plain text"})
        assert resp.status_code == 200


class TestCommandInjection:
    def test_unprotected_route_payload_reaches_the_sink(self, vuln_client):
        # The sink is simulated (see app.py) -- this asserts the payload
        # reaches it unmodified, which is what makes the pattern
        # dangerous in a real app using a real shell.
        resp = vuln_client.get("/vuln/cmdi", query_string={"host": "8.8.8.8; whoami"})
        assert resp.status_code == 200
        assert "whoami" in resp.get_json()["result"]

    def test_protected_route_blocks_same_payload(self, vuln_client):
        resp = vuln_client.get("/protected/cmdi", query_string={"host": "8.8.8.8; whoami"})
        assert resp.status_code == 403
        assert resp.get_json()["rule"] == "AEGIS-CMD-001"

    def test_protected_route_allows_clean_hostname(self, vuln_client):
        resp = vuln_client.get("/protected/cmdi", query_string={"host": "8.8.8.8"})
        assert resp.status_code == 200
