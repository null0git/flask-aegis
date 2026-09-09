# Deploying an application that uses Flask-Aegis

This guide covers running your Flask application (with Flask-Aegis
attached) behind a real WSGI server and reverse proxy — distinct from
`Dockerfile`/`docker-compose.yml` in the repo root, which package the
**playground** for local testing, not a template for deploying your
own application.

## WSGI server

Flask's built-in development server (`app.run()`, `flask run`) is not
meant for production regardless of whether Flask-Aegis is attached —
use a real WSGI server:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 myapp:app
```

Flask-Aegis has no gunicorn-specific configuration; it works the same
way under any WSGI server, with one thing to get right deliberately:

### Worker count and the in-memory rate limiter

`MemoryBackend` (the default `RateLimiter` backend) keeps its counters
in the process that created it. With gunicorn's default *sync* worker
model, each of your `-w N` workers is a **separate process** with its
own `MemoryBackend` — a policy configured as `"10/minute"` becomes,
in effect, `"10*N/minute"` across the whole deployment, since a given
client's requests land on different workers round-robin and each
worker counts independently.

Two ways to handle this:

1. **Use `RedisBackend`** so every worker (and every node, if you're
   running more than one machine) shares the same counters:

   ```python
   from flask_aegis.ratelimit import RedisBackend

   aegis = Aegis(
       app,
       profile="standard",
       rate_limit_backend=RedisBackend(url=os.environ["REDIS_URL"]),
   )
   ```

   This is the right choice once you're running more than one worker
   process or more than one node — see the README's Rate limiting
   section for the full `RedisBackend` API.

2. **Divide your intended limit by worker count** if you specifically
   don't want the Redis dependency yet (fine for a low-traffic
   deployment, not recommended long-term) — e.g. a true `"10/minute"`
   target with 4 sync workers means configuring `"2-3/minute"` per
   worker, accepting the imprecision from request distribution not
   being perfectly even.

The same reasoning applies to `flask_aegis.business.BusinessRules`'
quota/replay tracking (`ReplayGuard`, used by `@aegis.protect_action`)
and to `flask_aegis.websocket.WebSocketGuard`'s connection/message
counters — all three are in-memory-by-default for the same reason
(zero setup, correct for a single process) and need the same
worker-count consideration in a multi-process deployment.

### Async workers (gevent/eventlet/gthread)

Flask-Aegis's request pipeline does no I/O of its own beyond the
optional CAPTCHA verification HTTP call (`RecaptchaProvider.verify()`/
`HcaptchaProvider.verify()`, both synchronous `urllib` calls) and, if
configured, Redis calls for `RedisBackend`. Neither blocks in a way
that's specific to Flask-Aegis — the same considerations that apply to
any Flask extension making a synchronous outbound call under gunicorn's
gevent/eventlet workers apply here (monkey-patching makes `urllib` and
`redis-py` cooperative under those worker classes; no Flask-Aegis-side
configuration is needed either way).

## Reverse proxy

Run behind nginx, Caddy, or a cloud load balancer in front of gunicorn,
as you would any Flask app. Two things specific to getting Flask-Aegis's
signals right through a proxy:

### `remote_addr` and rate limiting

Flask-Aegis's default identity resolution (see
`RequestContext.from_flask_request`) falls back to `request.remote_addr`
for rate limiting when no API key or session cookie is present. Behind
a reverse proxy, `remote_addr` is the *proxy's* address for every
request unless the proxy sets `X-Forwarded-For` and your WSGI server is
configured to trust and use it:

```python
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)  # trust one hop of X-Forwarded-For
```

Without this, every request behind the proxy shares one identity for
rate-limiting purposes — effectively making per-client limits into a
single shared limit across all your traffic. Set `x_for` to the number
of proxy hops you actually have (1 for a single reverse proxy in front
of your app; more if there's a CDN in front of that).

### TLS termination and `Secure` cookies

`SecurityHeaders`' cookie hardening (see the README's Security headers
section) adds `Secure` to every `Set-Cookie` header by default. If TLS
terminates at your reverse proxy (the common case) and your app itself
serves plain HTTP internally, this is still correct — the cookie
reaches the browser over HTTPS either way — but if your proxy doesn't
forward a signal that the original request was HTTPS, Flask's own
session-cookie logic and any code that checks `request.is_secure` can
get confused. Set:

```python
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
```

alongside `x_for` above, so `request.is_secure` reflects the original
client-to-proxy scheme, not the proxy-to-app one.

## Environment-specific configuration

Don't hardcode CAPTCHA secrets, `SECRET_KEY`, or a Redis URL in your
source — read them from the environment:

```python
aegis = Aegis(
    app,
    profile=os.environ.get("AEGIS_PROFILE", "standard"),
    captcha={
        "provider": "recaptcha",
        "site_key": os.environ["RECAPTCHA_SITE_KEY"],
        "secret_key": os.environ["RECAPTCHA_SECRET_KEY"],
    },
    rate_limit_backend=RedisBackend(url=os.environ["REDIS_URL"]),
)
```

Use `flask aegis config export` (see the README's Config export
section) to snapshot the *resulting* configuration for an environment
as a sanity check before a deploy — it's secret-free, so it's safe to
attach to a PR or store alongside your deployment manifests as a record
of what was actually active.

## Health checks

A `/health`-style endpoint should generally use the `minimal` profile
(or no policy at all) so it takes Flask-Aegis's fast path — see the
README's Performance: the fast path section:

```python
@app.get("/health")
@aegis.protect("minimal")
def health():
    return "ok"
```

## Running `flask aegis audit --ci` in your own deployment pipeline

The same self-audit approach used in this repo's own
`.github/workflows/ci.yml` (see the `audit-self` job) is worth adopting
in your application's pipeline too — it catches the specific
misconfigurations Flask-Aegis knows about (missing rate limits,
`DEBUG=True`, CAPTCHA-required-without-a-provider, wildcard
CORS+credentials) before they reach production:

```yaml
- name: Flask-Aegis audit
  env:
    FLASK_APP: myapp:app
  run: flask aegis audit --ci
```
