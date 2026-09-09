"""
tests/fuzz/fuzz_policy.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fuzzes randomly generated policy inheritance graphs against the
invariant:

    A policy resolver must always produce a deterministic effective
    policy -- compiling the same policy name twice (from the same
    registered set) must yield an identical result.

Also asserts that the engine never raises anything other than
ConfigurationError / PolicyConflictError / PolicyNotFoundError for
malformed input -- an unexpected exception type here would mean a
config mistake crashes app startup with a confusing traceback instead
of a clear, documented error.

Run directly:
    python tests/fuzz/fuzz_policy.py [iterations] [seed]
"""
from __future__ import annotations

import os
import random
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from flask_aegis.exceptions import ConfigurationError, PolicyConflictError, PolicyNotFoundError
from flask_aegis.policy import Policy, PolicyEngine

_BOOL_FIELDS = ["csrf", "xss", "sqli", "traversal", "ssti", "cmdi", "ldap",
                "xpath", "header_injection", "csv_injection"]
_RATE_SPECS = [None, "5/minute", "10/hour", "not-a-rate", "0/second", "-1/minute", "abc/minute"]
_CAPTCHA_VALUES = [None, "always", "adaptive", "sometimes"]


def _random_name(rng: random.Random) -> str:
    length = rng.randint(1, 8)
    return "".join(rng.choice(string.ascii_lowercase + "_") for _ in range(length))


def _random_policy_kwargs(rng: random.Random) -> dict:
    kwargs = {}
    for f in _BOOL_FIELDS:
        if rng.random() < 0.4:
            kwargs[f] = rng.choice([True, False])
    if rng.random() < 0.5:
        kwargs["rate_limit"] = rng.choice(_RATE_SPECS)
    if rng.random() < 0.5:
        kwargs["captcha"] = rng.choice(_CAPTCHA_VALUES)
    if rng.random() < 0.5:
        kwargs["risk_threshold"] = rng.choice([None, -10, 0, 50, 200])
    return kwargs


def fuzz_policy(iterations: int = 500, seed: int = 1234) -> int:
    rng = random.Random(seed)
    checked = 0

    for i in range(iterations):
        checked += 1
        engine = PolicyEngine()
        names = [f"policy_{n}" for n in range(rng.randint(1, 12))]

        # Build a random forest of inheritance (each policy may extend an
        # earlier one, so no cycles are constructed by chance here -- cycle
        # rejection is exercised deliberately below).
        for idx, name in enumerate(names):
            extends = None
            if idx > 0 and rng.random() < 0.6:
                extends = rng.choice(names[:idx])
            try:
                engine.add(Policy(name=name, extends=extends, **_random_policy_kwargs(rng)))
            except (PolicyConflictError, ConfigurationError):
                pass
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(
                    f"[iteration {i}] engine.add() raised unexpected "
                    f"{type(exc).__name__}: {exc}"
                ) from exc

        target = rng.choice(names)
        try:
            first = engine.compile(target)
            second = engine.compile(target)
        except (ConfigurationError, PolicyConflictError, PolicyNotFoundError):
            continue  # expected for malformed config (e.g. bad rate_limit)
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"[iteration {i}] compile({target!r}) raised unexpected "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        if first != second:
            raise AssertionError(
                f"[iteration {i}] DETERMINISM VIOLATED: compiling "
                f"{target!r} twice gave different results.\n"
                f"first={first!r}\nsecond={second!r}"
            )

        # A third compile after compile_all() must also agree.
        try:
            all_compiled = engine.compile_all()
        except (ConfigurationError, PolicyConflictError, PolicyNotFoundError):
            continue
        if all_compiled[target] != first:
            raise AssertionError(
                f"[iteration {i}] compile_all() disagreed with compile() "
                f"for {target!r}.\ncompile()={first!r}\n"
                f"compile_all()={all_compiled[target]!r}"
            )

    # Deliberately exercise cycle rejection -- must always raise
    # PolicyConflictError, never anything else, never succeed silently.
    for i in range(min(iterations, 200)):
        engine = PolicyEngine()
        cycle_len = rng.randint(2, 5)
        cycle_names = [f"cyc_{n}" for n in range(cycle_len)]
        for idx, name in enumerate(cycle_names):
            extends = cycle_names[(idx - 1) % cycle_len]
            engine.add(Policy(name=name, extends=extends))
        try:
            engine.compile(cycle_names[0])
            raise AssertionError(
                f"[cycle iteration {i}] compiling a {cycle_len}-cycle "
                f"succeeded instead of raising PolicyConflictError"
            )
        except PolicyConflictError:
            pass  # expected

    return checked


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    s = int(sys.argv[2]) if len(sys.argv) > 2 else 1234
    total = fuzz_policy(iterations=n, seed=s)
    print(f"fuzz_policy: {total} random policy graphs checked, seed={s} -- determinism held, cycles always rejected")
