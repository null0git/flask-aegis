# Benchmark methodology

This directory exists so anyone can reproduce (or dispute) the
performance claims in the README rather than taking them on faith.

## What's measured

`flask aegis benchmark` (implemented in `flask_aegis/benchmark.py`)
drives requests through Flask's own `app.test_client()` rather than a
real HTTP server, and times each call with `time.perf_counter()`. This
is a deliberate choice, not a shortcut:

- Network I/O, WSGI server overhead (gunicorn/uWSGI worker dispatch,
  socket handling), and OS scheduling are **identical** across every
  configuration compared in a single run, since they're not exercised at
  all — the comparison isolates exactly one variable: **the Python-level
  overhead Flask-Aegis adds per request**.
- This means the suite answers "how much slower does Flask-Aegis make a
  request, in isolation" — not "what requests-per-second will my
  production server serve." The latter depends on your WSGI server,
  worker/thread count, network, and downstream I/O (database, external
  APIs), none of which this measures. Use a real load-testing tool
  (locust, wrk, hey) against a real deployment for that question.

## What's compared

Four configurations, all serving the identical trivial view function
(`echo one form field back as JSON`), so the only variable across rows
is the security layer in front of it:

1. **bare Flask** — no Flask-Aegis at all.
2. **Aegis (minimal)** — the `minimal` profile, which enables nothing
   inspectable, so `@aegis.protect(...)` takes the fast path and returns
   the view function completely unwrapped (see README → "Performance:
   the fast path"). The remaining delta vs. bare Flask isolates the cost
   of the one thing that *does* still run unconditionally: the global
   security-headers `after_request` hook.
3. **Aegis (standard)** — the recommended default profile: CSRF +
   XSS/SQLi/traversal/SSTI/command/header-injection detection, rate
   limiting.
4. **Aegis (strict)** — tighter thresholds, every injection category
   enabled, adaptive CAPTCHA (disabled for this benchmark specifically —
   see below).

Rate limits and CAPTCHA are deliberately overridden per-configuration so
a fixed-iteration run doesn't trip a throttle or challenge partway
through and start measuring "how fast does Flask-Aegis reject a
request" instead of "how fast does it allow one" — see
`build_comparison_apps()` in `flask_aegis/benchmark.py` for the exact
overrides and the comment explaining why `minimal` is deliberately left
untouched (to preserve the fast-path comparison).

## Reproducing these numbers

```bash
pip install -e ".[dev]"
flask aegis benchmark --iterations 1000 --warmup 100
```

or directly, without the CLI:

```python
from flask_aegis.benchmark import run_comparison, format_results_table
print(format_results_table(run_comparison(iterations=1000, warmup=100)))
```

## Results (this environment, for reference — re-run before citing)

Captured with `--iterations 1000 --warmup 100`:

```
Configuration          p50 (ms)   p95 (ms)   p99 (ms)  mean (ms)      req/s
---------------------------------------------------------------------------
bare Flask                0.310      0.511      0.672      0.351     2849.8
Aegis (minimal)           0.334      0.526      0.700      0.360     2777.3  (+0.009ms)
Aegis (standard)          0.409      0.534      0.674      0.424     2359.9  (+0.073ms)
Aegis (strict)            0.401      0.485      0.595      0.412     2427.6  (+0.061ms)
```

**Conditions this was captured under** (record these fields whenever you
re-run and report a number — a benchmark number without its conditions
isn't reproducible, it's a rumor):

| Field | Value |
|---|---|
| Python | 3.12.3 |
| Flask | 3.1.3 |
| flask-aegis | 0.2.0 |
| OS | Linux (containerized sandbox, single vCPU) |
| CPU count | 1 |
| Measurement method | `app.test_client()`, in-process, no network |
| Iterations / warmup | 1000 / 100 |

**How to read this:** on a single-vCPU environment with no real network
stack in the loop, `standard` adds roughly 0.07ms of mean per-request
latency over bare Flask, and `minimal`'s fast path keeps its overhead an
order of magnitude smaller (~0.01ms) than the fully-enabled profiles —
consistent with the fast path actually skipping the rule/risk engine
entirely rather than merely running a cheaper version of it (verified
directly in `tests/manual_smoke_test.py`'s
`"minimal profile fast path returns unwrapped view"` check, not just
inferred from timing). Treat the absolute millisecond figures as
specific to this environment; treat the *relative ordering* (bare <
minimal ≪ standard ≈ strict) and the fast-path mechanism itself as the
durable claim.

## Limitations of this methodology

- **Single-process, single-request-at-a-time.** No concurrency is
  exercised, so lock contention in `RateLimiter`'s `MemoryBackend` (which
  holds a single `threading.Lock`) isn't visible in these numbers. A
  concurrent-load benchmark against `RedisBackend` vs. `MemoryBackend`
  under real parallel traffic is a good candidate for a future addition
  to this directory.
- **One view function shape.** Real views do more work than echoing a
  form field, which would dilute Flask-Aegis's *relative* overhead
  (fixed per-request cost against a larger baseline) — these numbers are
  closer to a worst-case ratio than a typical one.
- **No detection-rule-triggering payloads in the timed path.** Every
  request in the benchmark is clean input that doesn't match any rule
  pattern. A request that *does* trigger multiple rules before being
  blocked takes a different, currently unmeasured code path.
