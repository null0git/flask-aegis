"""
flask_aegis.context
~~~~~~~~~~~~~~~~~~~~~

Request normalization: turns a Flask ``request`` object into a flat,
rule-friendly :class:`RequestContext` once per request, so every rule
doesn't have to re-derive "all the text values in this request" itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RequestContext:
    """Normalized view of one HTTP request, built once at the top of the
    pipeline and passed to every rule."""

    method: str
    path: str
    remote_addr: Optional[str]
    text_values: dict = field(default_factory=dict)
    """Flattened form fields + query params + shallow JSON string values,
    keyed by field name."""
    path_segments: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    identity: str = "anonymous"
    """Best-effort caller identity for rate limiting: session id, API key,
    or remote_addr, in that preference order."""

    raw_body: str = ""
    """Raw request body as text, when the content type suggests it's
    worth inspecting as a whole (e.g. XML) rather than only as flattened
    key/value pairs. Empty for ordinary form/JSON/query-string requests,
    where text_values already covers the meaningful content."""

    duplicate_params: dict = field(default_factory=dict)
    """{field_name: [value1, value2, ...]} for any query-string or form
    field that was submitted more than once with different values --
    the raw material for HTTP Parameter Pollution detection. Only
    populated when a name actually repeats; single-valued fields never
    appear here."""

    field_options_lookup: dict = field(default_factory=dict)
    """Populated from aegis.field(...) declarations for the current route."""

    def field_option(self, field_name: str, option: str, default=None):
        return self.field_options_lookup.get(field_name, {}).get(option, default)

    @classmethod
    def from_flask_request(cls, request, field_options=None) -> "RequestContext":
        text_values = {}
        for k, v in request.values.items():
            text_values[k] = v

        json_body = request.get_json(silent=True)
        if isinstance(json_body, dict):
            for k, v in json_body.items():
                if isinstance(v, str):
                    text_values[k] = v

        raw_body = ""
        content_type = (request.content_type or "").lower()
        if "xml" in content_type:
            try:
                raw_body = request.get_data(as_text=True) or ""
            except (UnicodeDecodeError, RuntimeError):
                raw_body = ""

        duplicate_params = {}
        for multidict in (request.args, request.form):
            for key in multidict:
                values = multidict.getlist(key)
                if len(values) > 1 and len(set(values)) > 1:
                    duplicate_params[key] = values

        identity = (
            request.headers.get("X-API-Key")
            or (request.cookies.get("session") and f"session:{request.cookies['session'][:16]}")
            or request.remote_addr
            or "anonymous"
        )

        return cls(
            method=request.method,
            path=request.path,
            remote_addr=request.remote_addr,
            text_values=text_values,
            path_segments=[s for s in request.path.split("/") if s],
            headers=dict(request.headers),
            identity=identity,
            raw_body=raw_body,
            duplicate_params=duplicate_params,
            field_options_lookup=field_options or {},
        )
