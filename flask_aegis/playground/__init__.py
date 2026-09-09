"""
flask_aegis.playground
~~~~~~~~~~~~~~~~~~~~~~~~

An interactive, browser-based playground for testing every attack class
Flask-Aegis detects, side by side with what happens to the identical
payload against unprotected code.

Launch it with:

    flask aegis playground

or, without needing FLASK_APP set:

    python -m flask_aegis.playground

WARNING: local testing only -- see the containment notes in
attacks.py's module docstring (same model as
examples/vulnerable_app/app.py: SQLi runs against in-memory SQLite,
traversal is confined to a temp sandbox, command injection and XXE
resolution are simulated rather than actually executed/resolved).
Binds to 127.0.0.1 by default; never expose this publicly.
"""
from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from .. import Aegis
from .attacks import ATTACKS


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(SECRET_KEY="playground-local-only", TESTING=False)

    aegis = Aegis(app, profile="minimal", mode="enforce")

    # One policy per attack, enabling exactly that attack's category (plus
    # any extra per-field opt-ins it needs) on top of a shared, generous
    # rate limit so testing isn't throttled mid-session.
    for attack in ATTACKS:
        policy_kwargs = {attack.category: True, "rate_limit": "10000/hour", "captcha": None}
        aegis.add_policy(f"playground_{attack.id}", **policy_kwargs)
        if attack.field_options:
            aegis.field(f"protected_{attack.id}", attack.field_name, **attack.field_options)

    @app.get("/")
    def index():
        from .. import __version__
        return render_template("index.html", attacks=ATTACKS, version=__version__)

    @app.get("/api/attacks")
    def list_attacks():
        return jsonify([
            {
                "id": a.id, "name": a.name, "category": a.category,
                "severity": a.severity, "description": a.description,
                "mitigation": a.mitigation, "example_payload": a.example_payload,
                "clean_example": a.clean_example, "field_name": a.field_name,
            }
            for a in ATTACKS
        ])

    def _run_vulnerable(attack, value=None):
        if value is None:
            if attack.id in ("xxe", "xml_bomb"):
                # XXE/XML-bomb detection depends on the raw XML body +
                # Content-Type (see RequestContext.raw_body) -- read the
                # body directly rather than a form/query field, so this
                # only works when the client POSTs with
                # Content-Type: application/xml.
                value = request.get_data(as_text=True) or request.values.get(attack.field_name, "")
            elif attack.id == "mass_assignment":
                # Mass assignment is about the *field name itself* being
                # dangerous (a request containing is_admin=true), not
                # dangerous content in a normally-named field -- so the
                # client submits the payload as the key, not as the
                # value of a fixed 'value' field. Read back whichever
                # key was actually submitted.
                keys = [k for k in request.values if k]
                value = keys[0] if keys else ""
            else:
                value = request.values.get(attack.field_name, "")
        result = attack.vulnerable_fn(value)
        if attack.id == "hpp":
            result["first_value"] = request.args.get("value")
            result["all_values"] = request.args.getlist("value")
        return result

    def _make_vuln_view(attack):
        def view():
            return jsonify(**_run_vulnerable(attack))
        view.__name__ = f"vuln_{attack.id}"
        return view

    def _make_protected_view(attack):
        def view():
            # If we reach this line at all, Aegis already allowed the
            # request through -- a BLOCK/THROTTLE/CHALLENGE finding never
            # gets here; it's short-circuited into Aegis's own
            # AegisBlocked error handler (registered by Aegis.init_app),
            # which returns the {"error": "blocked_by_aegis", "reason":
            # ..., "rule": ...} JSON body at the appropriate status code.
            #
            # A SANITIZE-decision finding (e.g. CSV/formula injection)
            # is different: the request is allowed through, but a
            # cleaned value is available via aegis.sanitized(). Surface
            # that distinction rather than silently using the raw value,
            # or the playground would look like nothing happened.
            raw_value = (
                (request.get_data(as_text=True) or "") if attack.id == "xxe"
                else request.values.get(attack.field_name, "")
            )
            sanitized_value = aegis.sanitized(attack.field_name)
            value = sanitized_value if sanitized_value is not None else raw_value
            result = _run_vulnerable(attack, value=value)
            if sanitized_value is not None:
                result["sanitized"] = True
                result["raw_value"] = raw_value
                result["sanitized_value"] = sanitized_value
            return jsonify(**result)
        view.__name__ = f"protected_{attack.id}"
        return aegis.protect(f"playground_{attack.id}")(view)

    for attack in ATTACKS:
        app.add_url_rule(
            f"/api/vuln/{attack.id}", endpoint=f"vuln_{attack.id}",
            view_func=_make_vuln_view(attack), methods=["GET", "POST"],
        )
        app.add_url_rule(
            f"/api/protected/{attack.id}", endpoint=f"protected_{attack.id}",
            view_func=_make_protected_view(attack), methods=["GET", "POST"],
        )

    return app


__all__ = ["create_app"]
