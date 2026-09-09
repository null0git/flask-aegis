import pytest
from flask import Flask, jsonify

from flask_aegis.openapi import OpenAPIGuard, OpenAPIValidationError

_SPEC = {
    "paths": {
        "/pets": {
            "post": {
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name", "age"],
                                "properties": {
                                    "name": {"type": "string", "minLength": 1, "maxLength": 50},
                                    "age": {"type": "integer", "minimum": 0, "maximum": 30},
                                    "species": {"type": "string", "enum": ["dog", "cat", "bird"]},
                                },
                            },
                        },
                    },
                },
            },
        },
        "/pets/{petId}": {
            "get": {
                "parameters": [
                    {"name": "petId", "in": "path", "required": True, "schema": {"type": "integer"}},
                    {"name": "verbose", "in": "query", "required": False, "schema": {"type": "boolean"}},
                ],
            },
        },
    },
}


@pytest.fixture
def guard():
    return OpenAPIGuard(_SPEC)


def test_valid_body_passes(guard):
    errors = guard.check("POST", "/pets", {}, {}, {"name": "Rex", "age": 5, "species": "dog"})
    assert errors == []


def test_missing_required_field(guard):
    errors = guard.check("POST", "/pets", {}, {}, {"age": 5})
    assert any("name" in e for e in errors)


def test_wrong_type(guard):
    errors = guard.check("POST", "/pets", {}, {}, {"name": "Rex", "age": "five"})
    assert any("expected type 'integer'" in e for e in errors)


def test_out_of_range(guard):
    errors = guard.check("POST", "/pets", {}, {}, {"name": "Rex", "age": 999})
    assert any("maximum" in e for e in errors)


def test_invalid_enum(guard):
    errors = guard.check("POST", "/pets", {}, {}, {"name": "Rex", "age": 5, "species": "dragon"})
    assert any("not one of" in e for e in errors)


def test_path_param_type_validated(guard):
    errors = guard.check("GET", "/pets/{petId}", {}, {"petId": "abc"}, None)
    assert any("expected type 'integer'" in e for e in errors)


def test_valid_path_param_passes(guard):
    errors = guard.check("GET", "/pets/{petId}", {}, {"petId": 42}, None)
    assert errors == []


def test_missing_operation_reports_error(guard):
    errors = guard.check("DELETE", "/nonexistent", {}, {}, None)
    assert len(errors) == 1


def test_flask_decorator_blocks_invalid_body(guard):
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", TESTING=True)

    @app.errorhandler(OpenAPIValidationError)
    def handle(e):
        return jsonify(errors=e.errors), 400

    @app.post("/pets")
    @guard.validate("POST", "/pets")
    def create_pet():
        return jsonify(status="ok")

    client = app.test_client()
    good = client.post("/pets", json={"name": "Rex", "age": 5})
    assert good.status_code == 200

    bad = client.post("/pets", json={})
    assert bad.status_code == 400
