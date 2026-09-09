"""
A minimal but realistic Flask-Aegis integration.

Run:
    pip install -e ..
    python basic_app.py
"""
from flask import Flask, jsonify, render_template, request

from flask_aegis import Aegis

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"

aegis = Aegis(
    app,
    profile="standard",
    captcha={
        "provider": "recaptcha",
        # Google's published reCAPTCHA test keys -- these always pass
        # verification and exist specifically for demos/local dev.
        # Replace with your own site/secret key pair before deploying.
        # https://developers.google.com/recaptcha/docs/faq#id-like-to-run-automated-tests-with-recaptcha-what-should-i-do
        "site_key": "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",
        "secret_key": "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe",
    },
)

# A custom policy that extends the "public_form" profile and tightens it.
aegis.add_policy(
    "registration",
    extends="public_form",
    rate_limit="10/minute",
    captcha="adaptive",
    risk_threshold=60,
)

# Per-field overrides: 'bio' is allowed to contain HTML, 'username' is not.
aegis.field("register", "username", max_length=32, xss=True)
aegis.field("register", "bio", max_length=5000, html=True)

aegis.headers(csp=True, hsts=True, frame_protection="DENY")


@app.get("/")
def index():
    return jsonify(message="Flask-Aegis is running.")


@app.post("/register")
@aegis.protect("registration")
def register():
    username = request.form.get("username", "")
    return jsonify(status="ok", username=username)


@app.post("/login")
@aegis.protect("authentication")
def login():
    return jsonify(status="ok")


# A comment field that should keep light formatting instead of being
# blocked outright -- sanitize rather than reject.
aegis.add_policy("comments", extends="public_form", rate_limit="30/minute", captcha=None)
aegis.field("comment", "body", xss_action="sanitize")


@app.get("/comment-form")
def comment_form():
    return render_template("comment_form.html")


@app.post("/comment")
@aegis.protect("comments")
def comment():
    # aegis.sanitized() returns the cleaned value when the XSS rule fired
    # with a SANITIZE decision; falls back to the raw value otherwise.
    body = aegis.sanitized("body", default=request.form.get("body", ""))
    return jsonify(status="ok", stored=body)


if __name__ == "__main__":
    app.run(debug=False)
