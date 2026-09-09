from flask_aegis.context import RequestContext
from flask_aegis.rules.hpp import ParameterPollutionRule
from flask_aegis.rules.nosqli import NoSQLInjectionRule
from flask_aegis.rules.open_redirect import OpenRedirectRule
from flask_aegis.rules.xxe import XXERule


def _ctx(**tv):
    return RequestContext(method="POST", path="/t", remote_addr="127.0.0.1", text_values=tv)


def test_nosqli_detects_operator_injection():
    assert NoSQLInjectionRule().check(_ctx(password='{"$ne": null}')) is not None


def test_nosqli_detects_where_tautology():
    assert NoSQLInjectionRule().check(_ctx(q="$where: 1==1")) is not None


def test_nosqli_ignores_clean_input():
    assert NoSQLInjectionRule().check(_ctx(username="alice")) is None


def test_nosqli_respects_field_opt_out():
    ctx = RequestContext(
        method="POST", path="/t", remote_addr="127.0.0.1",
        text_values={"note": "$gt is a MongoDB operator"},
        field_options_lookup={"note": {"nosqli": False}},
    )
    assert NoSQLInjectionRule().check(ctx) is None


def test_xxe_detects_external_entity():
    ctx = RequestContext(
        method="POST", path="/t", remote_addr="127.0.0.1",
        raw_body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    )
    assert XXERule().check(ctx) is not None


def test_xxe_ignores_clean_xml():
    ctx = RequestContext(method="POST", path="/t", remote_addr="127.0.0.1", raw_body="<foo>bar</foo>")
    assert XXERule().check(ctx) is None


def test_xxe_does_not_apply_without_raw_body():
    ctx = RequestContext(method="POST", path="/t", remote_addr="127.0.0.1")
    assert XXERule().applies_to(ctx) is False


def test_open_redirect_requires_explicit_field_opt_in():
    ctx = _ctx(next="//evil.com")  # no field_options_lookup at all
    assert OpenRedirectRule().check(ctx) is None


def test_open_redirect_detects_protocol_relative_when_opted_in():
    ctx = RequestContext(
        method="GET", path="/t", remote_addr="127.0.0.1",
        text_values={"next": "//evil.com"},
        field_options_lookup={"next": {"open_redirect": True}},
    )
    assert OpenRedirectRule().check(ctx) is not None


def test_open_redirect_allows_normal_relative_path_when_opted_in():
    ctx = RequestContext(
        method="GET", path="/t", remote_addr="127.0.0.1",
        text_values={"next": "/dashboard"},
        field_options_lookup={"next": {"open_redirect": True}},
    )
    assert OpenRedirectRule().check(ctx) is None


def test_open_redirect_detects_embedded_credentials_host():
    ctx = RequestContext(
        method="GET", path="/t", remote_addr="127.0.0.1",
        text_values={"next": "http://trusted.com@evil.com"},
        field_options_lookup={"next": {"open_redirect": True}},
    )
    assert OpenRedirectRule().check(ctx) is not None


def test_hpp_detects_differing_duplicate_values():
    ctx = RequestContext(
        method="GET", path="/t", remote_addr="127.0.0.1",
        duplicate_params={"role": ["user", "admin"]},
    )
    assert ParameterPollutionRule().check(ctx) is not None


def test_hpp_does_not_apply_without_duplicates():
    ctx = RequestContext(method="GET", path="/t", remote_addr="127.0.0.1")
    assert ParameterPollutionRule().applies_to(ctx) is False


def test_hpp_respects_field_opt_out():
    ctx = RequestContext(
        method="GET", path="/t", remote_addr="127.0.0.1",
        duplicate_params={"tags": ["a", "b"]},
        field_options_lookup={"tags": {"hpp": False}},
    )
    assert ParameterPollutionRule().check(ctx) is None
