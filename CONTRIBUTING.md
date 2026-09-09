# Contributing to Flask-Aegis

Thanks for considering a contribution. This project is alpha software
built with a specific bar in mind: **every claim in the README should be
something you could actually verify**, not something asserted and hoped
to be true. Contributions that raise that bar are the most welcome kind.

## Before you start

- Check open issues and pull requests to avoid duplicate work.
- For a substantial change (a new rule category, a new module), open an
  issue first to discuss the approach — it's a much smaller time
  investment than a full PR that turns out to need a different design.
- Read `SECURITY.md` if what you're reporting is a vulnerability in
  Flask-Aegis itself rather than a feature request or bug — that goes
  through a different channel.

## Development setup

```bash
git clone https://github.com/example/flask-aegis
cd flask-aegis
pip install -e ".[dev,redis]"
pytest
```

The `[dev]` extra installs `pytest`, `hypothesis`, `black`, and `ruff`.
Node.js (for the frontend sanitize parity test) is optional — that one
test is skipped automatically if Node isn't on your `PATH`.

## What a good pull request looks like

1. **Tests, not just code.** Every new rule, policy behavior, or bug fix
   needs a test demonstrating it — see `tests/` for the existing
   patterns. A fix without a regression test can regress again silently.
2. **New detection rules need a complete `RuleMeta`**: description,
   severity, category, mitigation, false-positive notes, and known
   limitations. A rule without documented false-positive behavior won't
   be merged — see any file in `flask_aegis/rules/` for the expected
   shape.
3. **Add the rule to a ruleset.** New rules go into a *new* dated entry
   in `flask_aegis/rulesets.py` (e.g. `_FULL_2030 = _FULL_2029 +
   [YourRule]`), never silently expanded into an existing frozen one —
   see the README's "Versioned rule sets" section for why that
   guarantee matters to existing users.
4. **Consider the playground.** If the attack class is a good fit for
   `examples/vulnerable_app/` or `flask_aegis/playground/attacks.py`'s
   containment model, add a paired vulnerable/protected demonstration
   there too — it's the best way to prove a rule actually catches
   something real, not just an isolated unit test.
5. **Run the fuzzers on anything touching a rule.** New or modified
   detection logic should survive `python tests/fuzz/fuzz_rules.py
   50000` without crashing before you rely on the lighter pytest-wrapped
   smoke pass alone.
6. **Update the README.** If you add a rule, a profile change, a CLI
   command, or a module, the corresponding README section needs to
   reflect it in the same PR — a feature undocumented in the README
   might as well not exist for a new user.

## Style

- `black` and `ruff` are configured via the `[dev]` extra; run them
  before opening a PR.
- Match the existing tone in docstrings and `RuleMeta` descriptions:
  concrete, specific about what's a real defense vs. a heuristic
  signal, and explicit about limitations rather than implying
  completeness.

## Reporting bugs

Open a GitHub issue with:
- What you expected vs. what happened.
- A minimal reproduction (a short Flask app snippet is ideal).
- Your Flask-Aegis version (`flask aegis config` or
  `python -c "import flask_aegis; print(flask_aegis.__version__)"`).

## Reporting security vulnerabilities

**Not through a public GitHub issue.** See `SECURITY.md` for the
private disclosure process.

## Code of conduct

This project follows the `CODE_OF_CONDUCT.md` in this repository.
