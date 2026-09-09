---
name: Feature request
about: Suggest a new rule, module, or capability
title: ""
labels: enhancement
assignees: ""
---

**What problem does this solve?**
What attack, workflow, or gap in coverage does this address? If it's a
new detection rule, name the attack class and, if you have one, a
reference (CVE, writeup, OWASP entry) describing it.

**Proposed approach**
How would this fit into Flask-Aegis's existing shape? For a new rule:
which category name, what severity, is it safe to enable broadly or
does it need to be opt-in per field (like `open_redirect`/
`csv_injection`)? For a new module: does it belong in the `Policy`
pipeline, or is it a standalone utility like `flask_aegis.openapi`/
`flask_aegis.graphql` (see the README's Phase 5 note on why those
aren't wired into `Policy`)?

**False positives**
What legitimate input could this incorrectly flag? Every rule in this
project ships with documented false-positive conditions — thinking
about this upfront saves a round-trip in review.

**Alternatives considered**
Any other way to address this you considered and why you didn't prefer it.

**Additional context**
Anything else — links, prior art in other WAF/security tools, etc.
