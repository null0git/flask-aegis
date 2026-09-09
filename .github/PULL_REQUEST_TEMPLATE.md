## What does this change?

<!-- One or two sentences. -->

## Checklist

- [ ] Tests added/updated (see `tests/` for the existing patterns)
- [ ] If this adds/changes a detection rule: `RuleMeta` includes
      description, severity, category, mitigation, false-positive
      notes, and limitations
- [ ] If this adds a rule: it's in a *new* ruleset entry in
      `flask_aegis/rulesets.py`, not silently added to an existing
      frozen one
- [ ] `pytest` passes locally
- [ ] For new/changed detection logic: ran
      `python tests/fuzz/fuzz_rules.py 50000` without a crash
- [ ] README updated for any user-facing change (new rule, profile
      change, CLI command, module)
- [ ] `black --check flask_aegis` and `ruff check flask_aegis` pass

## Related issue

<!-- Closes #... , or "N/A" -->
