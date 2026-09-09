from flask_aegis.context import RequestContext
from flask_aegis.rules.cmdi import CommandInjectionRule
from flask_aegis.rules.ldap_xpath import LDAPInjectionRule, XPathInjectionRule
from flask_aegis.rules.misc_injection import CSVInjectionRule, HeaderInjectionRule
from flask_aegis.rules.ssti import SSTIRule


def _ctx(**tv):
    return RequestContext(method="POST", path="/t", remote_addr="127.0.0.1", text_values=tv)


def test_ssti_detects_math_probe():
    assert SSTIRule().check(_ctx(name="{{7*7}}")) is not None


def test_ssti_detects_class_chain():
    assert SSTIRule().check(_ctx(name="{{ ''.__class__.__mro__ }}")) is not None


def test_ssti_ignores_clean_input():
    assert SSTIRule().check(_ctx(name="John Smith")) is None


def test_cmdi_detects_chained_command():
    assert CommandInjectionRule().check(_ctx(host="8.8.8.8; whoami")) is not None


def test_cmdi_detects_substitution():
    assert CommandInjectionRule().check(_ctx(host="$(id)")) is not None


def test_cmdi_ignores_clean_input():
    assert CommandInjectionRule().check(_ctx(host="8.8.8.8")) is None


def test_ldap_detects_filter_injection():
    assert LDAPInjectionRule().check(_ctx(uid="*)(uid=*))(|(uid=*")) is not None


def test_ldap_ignores_clean_input():
    assert LDAPInjectionRule().check(_ctx(uid="jsmith")) is None


def test_xpath_detects_boolean_tautology():
    assert XPathInjectionRule().check(_ctx(q="' or '1'='1")) is not None


def test_xpath_ignores_clean_input():
    assert XPathInjectionRule().check(_ctx(q="engineering")) is None


def test_header_injection_detects_crlf_with_cookie():
    ctx = _ctx(redirect="/ok\r\nSet-Cookie: admin=true")
    assert HeaderInjectionRule().check(ctx) is not None


def test_header_injection_ignores_plain_multiline_text():
    assert HeaderInjectionRule().check(_ctx(bio="line one\nline two")) is None


def test_csv_injection_is_opt_in_by_default():
    assert CSVInjectionRule().check(_ctx(amount="=cmd|'/c calc'!A1")) is None


def test_csv_injection_flags_formula_when_opted_in():
    ctx = RequestContext(
        method="POST", path="/t", remote_addr="127.0.0.1",
        text_values={"amount": "=cmd|'/c calc'!A1"},
        field_options_lookup={"amount": {"csv_injection": True}},
    )
    assert CSVInjectionRule().check(ctx) is not None
