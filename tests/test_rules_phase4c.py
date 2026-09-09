import base64
import json

from flask_aegis.context import RequestContext
from flask_aegis.rules.engine_injection import FormatStringRule, LaTeXInjectionRule, SSIInjectionRule
from flask_aegis.rules.homograph import HomographRule
from flask_aegis.rules.jwt_weak import JWTWeakAlgorithmRule
from flask_aegis.rules.mass_assignment import MassAssignmentRule
from flask_aegis.rules.redos import ReDoSRule
from flask_aegis.rules.xml_bomb import XMLBombRule


def _ctx(**tv):
    return RequestContext(method="POST", path="/t", remote_addr="127.0.0.1", text_values=tv)


def _opted_in(field_name, option, **tv):
    return RequestContext(
        method="POST", path="/t", remote_addr="127.0.0.1", text_values=tv,
        field_options_lookup={field_name: {option: True}},
    )


def _jwt(payload_dict, signature="sig"):
    header = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(b'{"sub":"123"}').decode().rstrip("=")
    return f"{header}.{body}.{signature}"


def test_mass_assignment_detects_is_admin():
    assert MassAssignmentRule().check(_ctx(is_admin="true")) is not None


def test_mass_assignment_detects_role():
    assert MassAssignmentRule().check(_ctx(role="admin")) is not None


def test_mass_assignment_ignores_normal_fields():
    assert MassAssignmentRule().check(_ctx(username="alice", email="a@b.com")) is None


def test_redos_requires_opt_in():
    assert ReDoSRule().check(_ctx(pattern="(a+)+")) is None


def test_redos_detects_nested_quantifier_when_opted_in():
    ctx = _opted_in("pattern", "redos", pattern="(a+)+$")
    assert ReDoSRule().check(ctx) is not None


def test_redos_allows_normal_pattern_when_opted_in():
    ctx = _opted_in("pattern", "redos", pattern="^[a-z]+$")
    assert ReDoSRule().check(ctx) is None


def test_jwt_detects_none_algorithm():
    token = _jwt({"alg": "none", "typ": "JWT"}, signature="")
    assert JWTWeakAlgorithmRule().check(_ctx(token=token)) is not None


def test_jwt_allows_normal_hs256_token():
    token = _jwt({"alg": "HS256", "typ": "JWT"})
    assert JWTWeakAlgorithmRule().check(_ctx(token=token)) is None


def test_jwt_ignores_non_jwt_shaped_string():
    assert JWTWeakAlgorithmRule().check(_ctx(name="Alice")) is None


def test_jwt_detects_none_algorithm_in_authorization_header():
    token = _jwt({"alg": "none"}, signature="")
    ctx = RequestContext(
        method="GET", path="/t", remote_addr="127.0.0.1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert JWTWeakAlgorithmRule().check(ctx) is not None


def test_homograph_requires_opt_in():
    assert HomographRule().check(_ctx(domain="app\u0430lication.com")) is None


def test_homograph_detects_cyrillic_mixed_with_latin_when_opted_in():
    ctx = _opted_in("domain", "homograph", domain="app\u0430lication.com")
    assert HomographRule().check(ctx) is not None


def test_homograph_allows_pure_latin_when_opted_in():
    ctx = _opted_in("domain", "homograph", domain="application.com")
    assert HomographRule().check(ctx) is None


def test_xml_bomb_detects_entity_reference_chain():
    payload = '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>'
    ctx = RequestContext(method="POST", path="/t", remote_addr="127.0.0.1", raw_body=payload)
    assert XMLBombRule().check(ctx) is not None


def test_xml_bomb_ignores_clean_xml():
    ctx = RequestContext(method="POST", path="/t", remote_addr="127.0.0.1", raw_body="<foo>bar</foo>")
    assert XMLBombRule().check(ctx) is None


def test_xml_bomb_flags_high_entity_count():
    entities = "".join(f'<!ENTITY e{i} "val{i}">' for i in range(10))
    ctx = RequestContext(
        method="POST", path="/t", remote_addr="127.0.0.1",
        raw_body=f"<!DOCTYPE foo [{entities}]><foo/>",
    )
    assert XMLBombRule().check(ctx) is not None


def test_ssi_injection_requires_opt_in():
    assert SSIInjectionRule().check(_ctx(comment='<!--#exec cmd="ls"-->')) is None


def test_ssi_injection_detected_when_opted_in():
    ctx = _opted_in("comment", "ssi_injection", comment='<!--#exec cmd="ls"-->')
    assert SSIInjectionRule().check(ctx) is not None


def test_latex_injection_detected_when_opted_in():
    ctx = _opted_in("name", "latex_injection", name="\\write18{rm -rf /}")
    assert LaTeXInjectionRule().check(ctx) is not None


def test_format_string_detects_percent_n_when_opted_in():
    ctx = _opted_in("name", "format_string", name="%n%n%n%n")
    assert FormatStringRule().check(ctx) is not None


def test_format_string_ignores_normal_text_when_opted_in():
    ctx = _opted_in("name", "format_string", name="John Smith")
    assert FormatStringRule().check(ctx) is None
