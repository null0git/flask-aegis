import pytest

from flask_aegis.playground import create_app
from flask_aegis.playground.attacks import ATTACKS


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_index_renders_every_attack_card(client):
    resp = client.get("/")
    assert resp.status_code == 200
    for attack in ATTACKS:
        assert f'data-attack="{attack.id}"'.encode() in resp.data


def test_attacks_api_lists_all_attacks(client):
    resp = client.get("/api/attacks")
    assert resp.status_code == 200
    body = resp.get_json()
    assert len(body) == len(ATTACKS)
    assert {a["id"] for a in body} == {a.id for a in ATTACKS}


def test_static_assets_served(client):
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


@pytest.mark.parametrize("attack", ATTACKS, ids=[a.id for a in ATTACKS])
def test_vulnerable_route_always_succeeds(client, attack):
    resp = client.get(f"/api/vuln/{attack.id}", query_string={attack.field_name: attack.example_payload})
    assert resp.status_code == 200


@pytest.mark.parametrize("attack", ATTACKS, ids=[a.id for a in ATTACKS])
def test_protected_route_allows_clean_input(client, attack):
    resp = client.get(f"/api/protected/{attack.id}", query_string={attack.field_name: attack.clean_example})
    assert resp.status_code == 200


@pytest.mark.parametrize(
    "attack", [a for a in ATTACKS if a.id not in ("csv_injection", "hpp", "xxe")],
    ids=lambda a: a.id,
)
def test_protected_route_blocks_malicious_payload(client, attack):
    resp = client.get(f"/api/protected/{attack.id}", query_string={attack.field_name: attack.example_payload})
    assert resp.status_code == 403
    assert resp.get_json()["rule"] is not None


def test_protected_xxe_requires_xml_content_type(client):
    xxe_payload = (
        '<?xml version="1.0"?><!DOCTYPE foo '
        '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    )
    resp = client.post("/api/protected/xxe", data=xxe_payload, content_type="application/xml")
    assert resp.status_code == 403
    assert resp.get_json()["rule"] == "AEGIS-XXE-001"


def test_protected_csv_injection_sanitizes_instead_of_blocking(client):
    resp = client.get(
        "/api/protected/csv_injection",
        query_string={"value": "=cmd|'/c calc'!A1"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["sanitized"] is True
    assert body["sanitized_value"].startswith("'=")


def test_vuln_hpp_returns_first_and_all_values(client):
    resp = client.get("/api/vuln/hpp?value=user&value=admin")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["first_value"] == "user"
    assert body["all_values"] == ["user", "admin"]


def test_protected_hpp_blocks_duplicate_params(client):
    # Unlike csv_injection, hpp's category is fully enabled on the
    # playground's protected policy -- Aegis blocks the duplicate
    # submission outright rather than letting the view demonstrate the
    # first-vs-all discrepancy. That's the correct security behavior:
    # compare against test_vuln_hpp_returns_first_and_all_values, which
    # shows what an *unprotected* route would have done with the same
    # duplicate params.
    resp = client.get("/api/protected/hpp?value=user&value=admin")
    assert resp.status_code == 403
    assert resp.get_json()["rule"] == "AEGIS-HPP-001"


def test_open_redirect_requires_field_level_opt_in_via_playground_config(client):
    # The playground wires aegis.field(..., open_redirect=True) itself,
    # so this should block without any extra setup from the test.
    resp = client.get("/api/protected/open_redirect", query_string={"next": "//evil.example.com"})
    assert resp.status_code == 403
    assert resp.get_json()["rule"] == "AEGIS-REDIRECT-001"
