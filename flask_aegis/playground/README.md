# Flask-Aegis Playground

An interactive, browser-based UI for testing every attack class
Flask-Aegis detects, side by side with the identical payload against
unprotected code.

## Run it

```bash
pip install -e .
flask aegis playground
# or, without needing FLASK_APP set:
python -m flask_aegis.playground
```

Then open **http://127.0.0.1:5050**.

## ⚠️ Local testing only

Same containment model as `examples/vulnerable_app/` (see its own
README for the full rationale) — this app contains genuinely
exploitable code for demonstration purposes:

- **SQLi** runs against an in-memory SQLite database seeded with fake
  data. Nothing persists, nothing outside the process is affected.
- **Path traversal** is confined to a temp sandbox directory created at
  startup and deleted on exit.
- **SSTI genuinely evaluates Jinja server-side** — this is real code
  execution capability on whatever machine runs it. Only run this
  locally, on a machine you're comfortable being attacked by inputs you
  type yourself.
- **Command injection** is simulated — the sink never calls a real
  shell.
- **XXE resolution** is simulated — the app extracts what an unsafe
  parser *would* have fetched via regex, rather than actually resolving
  the external entity.
- **Open redirect** shows the target textually instead of issuing a
  real HTTP redirect, since the UI uses `fetch()`, not browser
  navigation.
- **Insecure deserialization** is simulated — the sink never calls
  `pickle.loads()`/`unserialize()`, it only inspects the payload for
  recognizable serialization markers and describes what would happen.
- **SSRF (request field)** is simulated — the sink never makes a real
  outbound request; it describes what URL your backend would have
  fetched.
- **Prototype pollution** and **Expression Language injection** are
  both purely descriptive — neither involves a real JS runtime or Java/
  Spring evaluator; each shows what a vulnerable downstream consumer
  would do with the payload.

**Bind only to `127.0.0.1`** (the default) — never `0.0.0.0`, never
behind a public tunnel, never on a shared or production host.

## What each card does

Every attack class has a card with:

- A description and the recommended real-world mitigation.
- A payload textarea, pre-filled with a working example.
- A **Protected** toggle — off sends the payload to the raw vulnerable
  route; on sends it through the identical code wrapped in
  `@aegis.protect(...)`.
- A result panel showing the HTTP status, the blocking rule ID (if
  blocked), or the vulnerable route's simulated/contained output (if
  allowed) — including a distinct "sanitized" state for the CSV
  injection card, where Flask-Aegis allows the request through but
  cleans the value first rather than blocking outright.

See `flask_aegis/playground/attacks.py` for the full attack definitions
and exactly how each vulnerable sink is contained.
