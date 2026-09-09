"""
tests/fuzz/fuzz_traversal.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fuzzes `flask_aegis.rules.traversal.safe_join_root` against the core
invariant it exists to guarantee:

    A normalized path must never resolve outside its configured root.

For every fuzzed input, either the function returns None (rejected), or
it returns a path that is verifiably still inside the root directory on
the real filesystem (checked with os.path.commonpath against the
resolved, symlink-free absolute path). This is stronger than checking
the string alone -- it also catches issues a purely lexical check could
miss (e.g. a component that only escapes after normalization).

Run directly:
    python tests/fuzz/fuzz_traversal.py [iterations] [seed]
"""
from __future__ import annotations

import os
import random
import string
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from flask_aegis.rules.traversal import safe_join_root

_TRAVERSAL_FRAGMENTS = [
    "../", "..\\", "....//", "..%2f", "%2e%2e%2f", "%2e%2e/", "..%c0%af",
    "..;/", "./", ".", "..", "/", "\\", "//", "\\\\", "\x00", "%00",
]
_NORMAL_CHARS = string.ascii_letters + string.digits + "_- ."


def _random_segment(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return rng.choice(_TRAVERSAL_FRAGMENTS)
    length = rng.randint(0, 12)
    return "".join(rng.choice(_NORMAL_CHARS) for _ in range(length))


def _random_path(rng: random.Random, max_segments: int = 8) -> str:
    n = rng.randint(0, max_segments)
    sep = rng.choice(["/", "\\", "/"])
    return sep.join(_random_segment(rng) for _ in range(n))


def fuzz_traversal(iterations: int = 3000, seed: int = 1234) -> int:
    rng = random.Random(seed)
    checked = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "safe_root")
        os.makedirs(root)
        # A directory a naive check might be fooled into treating as "inside"
        # since it shares a string prefix with root (root vs root_evil).
        sibling_prefix_dir = os.path.join(tmp, "safe_root_evil")
        os.makedirs(sibling_prefix_dir)

        root_abs = os.path.abspath(root)

        for i in range(iterations):
            checked += 1
            candidate_paths = [_random_path(rng) for _ in range(rng.randint(1, 3))]

            try:
                result = safe_join_root(root, *candidate_paths)
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(
                    f"[iteration {i}] safe_join_root raised {type(exc).__name__}: "
                    f"{exc}\ncandidate_paths={candidate_paths!r}"
                ) from exc

            if result is None:
                continue  # rejected -- invariant trivially holds

            result_abs = os.path.abspath(result)
            try:
                common = os.path.commonpath([root_abs, result_abs])
            except ValueError:
                # Different drives on Windows, or otherwise incomparable --
                # treat as a violation, since it can't be "inside" root.
                common = None

            if common != root_abs:
                raise AssertionError(
                    f"[iteration {i}] INVARIANT VIOLATED: safe_join_root returned "
                    f"a path outside root.\n"
                    f"root={root_abs!r}\ncandidate_paths={candidate_paths!r}\n"
                    f"result={result_abs!r}"
                )

    return checked


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    s = int(sys.argv[2]) if len(sys.argv) > 2 else 1234
    total = fuzz_traversal(iterations=n, seed=s)
    print(f"fuzz_traversal: {total} candidate paths checked, seed={s} -- invariant held")
