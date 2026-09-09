# ⚠️ Vulnerable test application — local use only

This directory contains a Flask app with **deliberately vulnerable
endpoints**, used by `tests/security/test_vulnerable_app.py` to
demonstrate what Flask-Aegis actually catches, against real (if
contained) vulnerable code — not just asserted in the abstract.

## Do not deploy this application anywhere

- Bind only to `127.0.0.1` (the default in `app.py`) — never `0.0.0.0`,
  never behind a public tunnel, never on a shared or production host.
- The `/vuln/ssti` route genuinely evaluates user-supplied Jinja
  templates server-side. This is real code execution capability on
  whatever machine runs it. Only run this on a machine you're
  comfortable being attacked by inputs you type yourself.
- The `/vuln/sqli` route runs against an **in-memory SQLite database**
  seeded with two fake users — nothing persists, nothing outside the
  process is affected.
- The `/vuln/traversal` route is confined to a temporary sandbox
  directory created at startup and deleted on exit — it cannot read
  real files on your system outside that sandbox.
- The `/vuln/cmdi` route is **simulated**: it never calls `subprocess`
  or `os.system`. The "vulnerable" sink is a fake function that returns
  a string describing what it would have run. This is intentional —
  see the module docstring in `app.py`.

## What it's for

Each vulnerability class has three routes:

| Route | Behavior |
|---|---|
| `/vuln/<name>` | The vulnerable pattern, no Flask-Aegis protection. |
| `/protected/<name>` | The identical pattern, wrapped in `@aegis.protect(...)`. |
| `/safe/traversal` | (traversal only) The actually-correct fix, `safe_join_root`, for comparison — shown independent of whether Aegis is attached. |

Run the app:

```bash
pip install -e ../..
python app.py
```

Then, in another terminal:

```bash
curl "http://127.0.0.1:5001/vuln/xss?name=<script>alert(1)</script>"
curl "http://127.0.0.1:5001/protected/xss?name=<script>alert(1)</script>"
```

Or run the automated comparison:

```bash
pytest tests/security/test_vulnerable_app.py -v
```
