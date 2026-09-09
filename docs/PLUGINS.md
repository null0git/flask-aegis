# Writing a Flask-Aegis plugin

Flask-Aegis has two plugin points: a custom **detection rule** and a
custom **CAPTCHA provider**. Both follow the same shape as every
built-in one — there's no separate "plugin API" to learn beyond the
base classes the built-ins already use.

## Custom detection rules

Subclass `flask_aegis.rules.base.Rule`, register an instance, then
enable its category on a policy the same way you'd enable `xss` or
`sqli`:

```python
from flask import Flask, jsonify, request
from flask_aegis import Aegis
from flask_aegis.rules.base import Rule, RuleMeta
from flask_aegis.decisions import Decision, Finding

class NoEmojiUsernameRule(Rule):
    meta = RuleMeta(
        rule_id="ACME-USERNAME-001",
        category="no_emoji_username",
        severity="low",
        description="Blocks emoji in usernames.",
        mitigation="Reject the request.",
        false_positive_notes="None expected -- usernames rarely need emoji.",
        limitations="Only checks a fixed set of emoji code point ranges.",
    )

    def check(self, ctx):
        username = ctx.text_values.get("username", "")
        if any(0x1F300 <= ord(c) <= 0x1FAFF for c in username):
            return Finding(
                rule_id=self.meta.rule_id,
                decision=Decision.BLOCK,
                message="Emoji not allowed in username",
            )
        return None

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only"
aegis = Aegis(app, profile="minimal")

aegis.register_detector(NoEmojiUsernameRule())
aegis.add_policy("signup", no_emoji_username=True, rate_limit="100/minute")

@app.post("/signup")
@aegis.protect("signup")
def signup():
    return jsonify(ok=True)
```

`no_emoji_username=True` here isn't a field Flask-Aegis's `Policy`
class ships with — `aegis.add_policy()` routes any keyword that isn't
a recognized built-in field into the policy's `extra` dict
automatically, and the request pipeline checks `policy.extra` for any
category name a registered rule declares that isn't one of the
built-in categories. This is the whole mechanism; there's no
registration step beyond `register_detector()` and no policy-schema
change required to add a new category.

**This example is directly runnable and tested** — see
`tests/test_plugin_rules.py` for the exact same rule exercised end to
end (emoji blocked with a 403 and the right rule ID, clean input
allowed, the rule visible in `aegis.rules.all()`, and — importantly —
staying completely silent on a policy that never opts into
`no_emoji_username`, so a plugin can't fire on a route that never
asked for it).

### What a complete `RuleMeta` looks like

Every built-in rule documents five things, and a plugin rule should
too — see any file in `flask_aegis/rules/` for the pattern:

| Field | What it's for |
|---|---|
| `rule_id` | A stable identifier (`ACME-USERNAME-001` above) — shows up in `flask aegis rules`, in blocked-response JSON, and in security events. |
| `severity` | `low` / `medium` / `high` / `critical` — feeds the risk engine's scoring. |
| `description` | What the rule detects, specifically enough that someone reading `flask aegis rules` output understands it without opening the source. |
| `mitigation` | What actually fixes the underlying problem — not just "block the request," but the durable code-level fix, the way `AEGIS-SQLI-001`'s says "use parameterized queries," not just "this rule blocks it." |
| `false_positive_notes` | What legitimate input could trigger this and how to exempt it (`aegis.field(route, field_name, your_category=False)` works the same way for a plugin category as a built-in one). |
| `limitations` | What this rule doesn't catch — stated plainly, not implied by omission. |

### Opt-in vs. opt-out categories

Whether your rule's `check()` should apply by default or require an
explicit per-field opt-in follows the same judgment call the built-ins
make — see `AEGIS-CSV-001` (CSV injection) and `AEGIS-REDIRECT-001`
(open redirect) for the opt-in pattern (`ctx.field_option(field_name,
"your_category", default=False)`), versus `AEGIS-XSS-001` for the
opt-out pattern (`default=True`). Opt-in is the right choice when your
rule's pattern legitimately collides with normal input on most fields;
opt-out is right when it's dangerous everywhere by default.

## Custom CAPTCHA providers

Subclass `flask_aegis.captcha.base.CaptchaProvider` and register it —
`flask_aegis/captcha/hcaptcha.py` (shipped with the package) is a
complete worked example, built the exact same way a third-party
provider would be:

```python
from flask_aegis.captcha.base import CaptchaProvider

class MyProvider(CaptchaProvider):
    name = "my_provider"

    def __init__(self, site_key, secret_key):
        self.site_key = site_key
        self._secret_key = secret_key  # never exposed via public_config()

    def public_config(self):
        return {"provider": self.name, "site_key": self.site_key}  # no secret here

    def verify(self, token, remote_ip=None):
        ...  # server-to-server POST to your provider's verification API

    def render_jinja(self):
        return f'<div class="my-widget" data-sitekey="{self.site_key}"></div>'

aegis.register_provider("my_provider", MyProvider)
# Now usable via: Aegis(app, captcha={"provider": "my_provider", ...})
```

**The one rule that matters more than any other here:** `secret_key`
(or your provider's equivalent) is read only inside `verify()`, which
makes a server-side call — it must never appear in `public_config()`,
in `render_jinja()`'s output, or anywhere else a client could observe
it. `hcaptcha.py` and `recaptcha.py` both mark it with a leading
underscore (`self._secret_key`) specifically as a visual signal of
that boundary; follow the same convention.

## Where plugin categories don't fit

The four Phase 5 modules — `flask_aegis.openapi`, `flask_aegis.graphql`,
`flask_aegis.websocket`, and business-logic protection
(`flask_aegis.business`) — are **not** part of the `Policy`/rule-category
plugin system described above. Each needs something a per-request rule
category can't express (a loaded OpenAPI spec, a persistent
per-connection WebSocket guard, a non-HTTP connection lifecycle) — see
the README's Roadmap section for why they're standalone utilities
instead. If what you're building looks more like one of those than
like a request-field check, model it the same way: a small,
independently-usable class with its own `.check()`/`.protect()`
surface, rather than trying to force it through `register_detector()`.
