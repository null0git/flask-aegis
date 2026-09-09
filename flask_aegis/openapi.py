"""
flask_aegis.openapi
~~~~~~~~~~~~~~~~~~~~~

Derives request validation from an OpenAPI 3.x specification: required
parameters, parameter types, and request-body schema (a practical
subset of JSON Schema -- type, required, enum, string length/pattern,
numeric min/max, array item validation, nested objects). No external
schema-validation dependency: this is a deliberately small,
dependency-free validator covering the JSON Schema constructs that
appear in real-world OpenAPI specs, not a complete implementation of
the spec (no $ref resolution across external files, no allOf/oneOf/
anyOf composition, no format-specific validators beyond a few common
ones). For a full JSON Schema implementation, use the `jsonschema`
package directly -- this module exists so basic OpenAPI-derived
validation works without adding a dependency for it.

Example
-------
>>> from flask_aegis.openapi import OpenAPIGuard
>>> guard = OpenAPIGuard.from_file("openapi.yaml")
>>> @app.post("/pets")
... @guard.validate("POST", "/pets")
... def create_pet():
...     ...
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .exceptions import AegisError

_FORMAT_PATTERNS = {
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "date": re.compile(r"^\d{4}-\d{2}-\d{2}$"),
    "date-time": re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
    "uuid": re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
    ),
}

_TYPE_CHECKERS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


class OpenAPIValidationError(AegisError):
    """Raised by :meth:`OpenAPIGuard.check` when a request fails schema
    validation. ``errors`` lists every violation found, not just the
    first, so a client gets a complete picture in one round-trip."""

    def __init__(self, errors: list):
        super().__init__("; ".join(errors))
        self.errors = errors


def _validate_schema(value: Any, schema: dict, path: str, errors: list) -> None:
    """Recursively validate ``value`` against a (subset of) JSON Schema
    ``schema``, appending human-readable messages to ``errors``."""
    if schema is None:
        return

    expected_type = schema.get("type")
    if expected_type and expected_type in _TYPE_CHECKERS:
        if not _TYPE_CHECKERS[expected_type](value):
            errors.append(f"{path}: expected type '{expected_type}', got {type(value).__name__}")
            return  # further checks would be meaningless against the wrong type

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value {value!r} is not one of {schema['enum']}")

    fmt = schema.get("format")
    if fmt in _FORMAT_PATTERNS and isinstance(value, str):
        if not _FORMAT_PATTERNS[fmt].match(value):
            errors.append(f"{path}: value does not match format '{fmt}'")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: length {len(value)} is less than minLength {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: length {len(value)} exceeds maxLength {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: value does not match pattern '{schema['pattern']}'")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: value {value} is less than minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: value {value} exceeds maximum {schema['maximum']}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: has {len(value)} items, fewer than minItems {schema['minItems']}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: has {len(value)} items, more than maxItems {schema['maxItems']}")
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(value):
                _validate_schema(item, item_schema, f"{path}[{i}]", errors)

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for req_key in required:
            if req_key not in value:
                errors.append(f"{path}: missing required property '{req_key}'")
        for key, val in value.items():
            if key in properties:
                _validate_schema(val, properties[key], f"{path}.{key}", errors)
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property '{key}'")


@dataclass
class Operation:
    method: str
    path: str
    parameters: list = field(default_factory=list)
    request_body_schema: Optional[dict] = None
    request_body_required: bool = False


class OpenAPIGuard:
    """Loads an OpenAPI 3.x spec and validates requests against the
    operation matching a given method + path template.

    Path templates use OpenAPI's `{param}` syntax and must match the
    spec's `paths` keys exactly (e.g. `/pets/{petId}`) -- this does not
    do Flask route-to-OpenAPI-path inference, since that mapping isn't
    always 1:1 (a Flask `<int:pet_id>` converter has no fixed
    correspondence to an OpenAPI path template without you saying so).
    """

    def __init__(self, spec: dict):
        self.spec = spec
        self._operations: dict = self._index_operations(spec)

    @classmethod
    def from_file(cls, path: str) -> "OpenAPIGuard":
        with open(path) as f:
            content = f.read()
        if path.endswith((".yaml", ".yml")):
            import yaml
            spec = yaml.safe_load(content)
        else:
            spec = json.loads(content)
        return cls(spec)

    @staticmethod
    def _index_operations(spec: dict) -> dict:
        operations = {}
        for path_template, path_item in (spec.get("paths") or {}).items():
            for method, op in path_item.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                request_body_schema = None
                request_body_required = False
                request_body = op.get("requestBody")
                if request_body:
                    request_body_required = bool(request_body.get("required"))
                    content = request_body.get("content", {})
                    json_content = content.get("application/json", {})
                    request_body_schema = json_content.get("schema")
                operations[(method.upper(), path_template)] = Operation(
                    method=method.upper(),
                    path=path_template,
                    parameters=op.get("parameters", []),
                    request_body_schema=request_body_schema,
                    request_body_required=request_body_required,
                )
        return operations

    def check(self, method: str, path_template: str, query_params: dict,
              path_params: dict, body: Any) -> list:
        """Validate a request against the operation for
        ``(method, path_template)``. Returns a list of error strings
        (empty if valid). Raises nothing itself -- callers decide what
        to do with the result (see :meth:`validate` for the
        Flask-integrated version that raises/blocks automatically)."""
        op = self._operations.get((method.upper(), path_template))
        if op is None:
            return [f"No OpenAPI operation defined for {method} {path_template}"]

        errors: list = []
        for param in op.parameters:
            name = param.get("name")
            location = param.get("in")
            required = param.get("required", False)
            schema = param.get("schema", {})

            source = {"query": query_params, "path": path_params}.get(location)
            if source is None:
                continue  # header/cookie params not modeled here

            if name not in source:
                if required:
                    errors.append(f"{location} parameter '{name}' is required but missing")
                continue
            _validate_schema(source[name], schema, f"{location}.{name}", errors)

        if op.request_body_schema is not None:
            if body is None:
                if op.request_body_required:
                    errors.append("request body is required but missing")
            else:
                _validate_schema(body, op.request_body_schema, "body", errors)

        return errors

    def validate(self, method: str, path_template: str) -> Callable:
        """Decorator: validates the current Flask request against the
        given operation before the view runs, raising
        :class:`OpenAPIValidationError` on any violation.

        >>> @app.post("/pets")
        ... @guard.validate("POST", "/pets")
        ... def create_pet():
        ...     ...
        """
        def decorator(view_func: Callable) -> Callable:
            import functools

            from flask import request

            @functools.wraps(view_func)
            def wrapped(*args, **kwargs):
                body = request.get_json(silent=True)
                errors = self.check(
                    method, path_template,
                    query_params=dict(request.args),
                    path_params=dict(kwargs),
                    body=body,
                )
                if errors:
                    raise OpenAPIValidationError(errors)
                return view_func(*args, **kwargs)

            return wrapped

        return decorator
