import base64

from flask_aegis.context import RequestContext
from flask_aegis.rules.deserialization import DeserializationRule
from flask_aegis.rules.el_injection import ELInjectionRule
from flask_aegis.rules.proto_pollution import PrototypePollutionRule
from flask_aegis.rules.ssrf_field import SSRFFieldRule


def _ctx(**tv):
    return RequestContext(method="POST", path="/t", remote_addr="127.0.0.1", text_values=tv)


def test_deserialization_detects_pickle_global_opcode():
    assert DeserializationRule().check(_ctx(data="c__main__\nsome_class\n")) is not None


def test_deserialization_detects_php_serialized_object():
    payload = 'O:8:"stdClass":1:{s:4:"prop";s:3:"val";}'
    assert DeserializationRule().check(_ctx(data=payload)) is not None


def test_deserialization_detects_base64_encoded_java_magic():
    payload = base64.b64encode(b"\xac\xed\x00\x05payload").decode()
    assert DeserializationRule().check(_ctx(data=payload)) is not None


def test_deserialization_detects_base64_encoded_pickle_header():
    payload = base64.b64encode(b"\x80\x04\x95somepickledata").decode()
    assert DeserializationRule().check(_ctx(data=payload)) is not None


def test_deserialization_ignores_clean_input():
    assert DeserializationRule().check(_ctx(data="just a normal comment")) is None


def test_deserialization_ignores_harmless_base64():
    assert DeserializationRule().check(_ctx(data="SGVsbG8gV29ybGQh")) is None  # "Hello World!"


def test_ssrf_field_requires_explicit_opt_in():
    ctx = _ctx(webhook_url="http://169.254.169.254/")
    assert SSRFFieldRule().check(ctx) is None


def test_ssrf_field_detects_metadata_ip_when_opted_in():
    ctx = RequestContext(
        method="POST", path="/t", remote_addr="127.0.0.1",
        text_values={"webhook_url": "http://169.254.169.254/latest/meta-data/"},
        field_options_lookup={"webhook_url": {"ssrf_field": True}},
    )
    assert SSRFFieldRule().check(ctx) is not None


def test_ssrf_field_detects_file_scheme_when_opted_in():
    ctx = RequestContext(
        method="POST", path="/t", remote_addr="127.0.0.1",
        text_values={"webhook_url": "file:///etc/passwd"},
        field_options_lookup={"webhook_url": {"ssrf_field": True}},
    )
    assert SSRFFieldRule().check(ctx) is not None


def test_ssrf_field_allows_public_url_when_opted_in():
    ctx = RequestContext(
        method="POST", path="/t", remote_addr="127.0.0.1",
        text_values={"webhook_url": "https://example.com/hook"},
        field_options_lookup={"webhook_url": {"ssrf_field": True}},
    )
    assert SSRFFieldRule().check(ctx) is None


def test_proto_pollution_detects_dunder_proto():
    assert PrototypePollutionRule().check(_ctx(key="__proto__")) is not None


def test_proto_pollution_detects_constructor_prototype():
    assert PrototypePollutionRule().check(_ctx(key="constructor.prototype.polluted")) is not None


def test_proto_pollution_ignores_clean_input():
    assert PrototypePollutionRule().check(_ctx(key="normal_key")) is None


def test_el_injection_detects_spring_el_runtime_exec():
    payload = '${T(java.lang.Runtime).getRuntime().exec("id")}'
    assert ELInjectionRule().check(_ctx(name=payload)) is not None


def test_el_injection_detects_ognl_static_call():
    payload = '@java.lang.Runtime@getRuntime().exec("id")'
    assert ELInjectionRule().check(_ctx(name=payload)) is not None


def test_el_injection_ignores_clean_input():
    assert ELInjectionRule().check(_ctx(name="John Smith")) is None


def test_el_injection_ignores_plain_dollar_brace():
    assert ELInjectionRule().check(_ctx(price="${100}")) is None
