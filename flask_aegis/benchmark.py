"""
flask_aegis.benchmark
~~~~~~~~~~~~~~~~~~~~~~~

Benchmark suite comparing bare Flask against Flask-Aegis at each built-in
profile, backing the `flask aegis benchmark` CLI command.

Measurement approach: requests are driven through Flask's own test
client (`app.test_client()`) rather than a real HTTP server, so results
measure Flask-Aegis's added per-request overhead in isolation --
network, WSGI-server, and OS socket overhead are identical across every
configuration being compared and so cancel out of the comparison. This
is the right tool for answering "how much does Flask-Aegis add," and the
wrong tool for answering "what RPS will my server serve in production"
(that number depends on your WSGI server, worker count, and network,
none of which this measures). Use a real load-testing tool (locust, wrk,
hey) against a real deployment for the latter.
"""
from __future__ import annotations

import gc
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class BenchmarkResult:
    label: str
    iterations: int
    latencies_ms: list = field(default_factory=list)

    @property
    def p50(self) -> float:
        return statistics.median(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def p95(self) -> float:
        return _percentile(self.latencies_ms, 95)

    @property
    def p99(self) -> float:
        return _percentile(self.latencies_ms, 99)

    @property
    def mean(self) -> float:
        return statistics.mean(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def total_seconds(self) -> float:
        return sum(self.latencies_ms) / 1000.0

    @property
    def requests_per_second(self) -> float:
        return self.iterations / self.total_seconds if self.total_seconds > 0 else 0.0


def _percentile(values: list, pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(ordered) - 1)
    if f == c:
        return ordered[f]
    return ordered[f] + (ordered[c] - ordered[f]) * (k - f)


def run_benchmark(
    client_factory: Callable[[], object],
    request_fn: Callable[[object], None],
    iterations: int = 500,
    warmup: int = 50,
    label: str = "",
) -> BenchmarkResult:
    """Runs ``request_fn(client)`` ``iterations`` times against a fresh
    client from ``client_factory()``, timing each call. ``warmup`` calls
    beforehand are discarded (JIT/cache warmup, first-request Flask
    setup) and not counted in the result.
    """
    client = client_factory()

    for _ in range(warmup):
        request_fn(client)

    gc.collect()
    gc.disable()
    try:
        latencies = []
        for _ in range(iterations):
            start = time.perf_counter()
            request_fn(client)
            latencies.append((time.perf_counter() - start) * 1000.0)
    finally:
        gc.enable()

    return BenchmarkResult(label=label, iterations=iterations, latencies_ms=latencies)


def build_comparison_apps():
    """Returns a dict of {label: app_factory} comparing bare Flask
    against Flask-Aegis at each built-in profile, all serving the
    identical trivial view function so the only variable is the
    security layer in front of it."""
    from flask import Flask, jsonify, request

    from flask_aegis import Aegis

    def _make_view(app, aegis=None, policy_name=None):
        if aegis is not None and policy_name is not None:
            @app.post("/bench")
            @aegis.protect(policy_name)
            def bench():
                return jsonify(echo=request.form.get("field", ""))
        else:
            @app.post("/bench")
            def bench():
                return jsonify(echo=request.form.get("field", ""))

    def bare_flask():
        app = Flask(__name__)
        app.config.update(SECRET_KEY="bench", TESTING=True)
        _make_view(app)
        return app

    def aegis_profile(profile_name):
        def factory():
            from flask_aegis.profiles import get_profile

            app = Flask(__name__)
            app.config.update(SECRET_KEY="bench", TESTING=True)
            aegis = Aegis(app, profile=profile_name, captcha=None)

            defaults = get_profile(profile_name)
            overrides = {"captcha": None}
            # Only raise the rate limit ceiling for profiles that would
            # otherwise throttle partway through a fixed-iteration run --
            # leaving it untouched for profiles with rate_limit=None
            # (e.g. "minimal") preserves the fast-path no-op comparison,
            # which is the whole point of including that profile here.
            if defaults.get("rate_limit") is not None:
                overrides["rate_limit"] = "1000000/hour"
            aegis.add_policy("bench", extends=profile_name, **overrides)
            _make_view(app, aegis, "bench")
            return app
        return factory

    return {
        "bare Flask": bare_flask,
        "Aegis (minimal)": aegis_profile("minimal"),
        "Aegis (standard)": aegis_profile("standard"),
        "Aegis (strict)": aegis_profile("strict"),
    }


def run_comparison(iterations: int = 500, warmup: int = 50) -> list:
    """Runs the full bare-Flask-vs-profiles comparison and returns a
    list of BenchmarkResult, in the order defined by
    build_comparison_apps()."""
    apps = build_comparison_apps()
    results = []

    for label, factory in apps.items():
        app = factory()

        def request_fn(client, app=app):
            client.post("/bench", data={"field": "just a normal value, nothing flagged"})

        result = run_benchmark(
            client_factory=app.test_client,
            request_fn=request_fn,
            iterations=iterations,
            warmup=warmup,
            label=label,
        )
        results.append(result)

    return results


def format_results_table(results: list) -> str:
    lines = []
    header = f"{'Configuration':<20} {'p50 (ms)':>10} {'p95 (ms)':>10} {'p99 (ms)':>10} {'mean (ms)':>10} {'req/s':>10}"
    lines.append(header)
    lines.append("-" * len(header))
    baseline = results[0].mean if results else 1.0
    for r in results:
        overhead = f"  (+{r.mean - baseline:.3f}ms)" if r is not results[0] else ""
        lines.append(
            f"{r.label:<20} {r.p50:>10.3f} {r.p95:>10.3f} {r.p99:>10.3f} "
            f"{r.mean:>10.3f} {r.requests_per_second:>10.1f}{overhead}"
        )
    return "\n".join(lines)
