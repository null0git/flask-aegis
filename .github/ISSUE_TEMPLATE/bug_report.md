---
name: Bug report
about: Something isn't working the way it should
title: ""
labels: bug
assignees: ""
---

**Describe the bug**
A clear description of what's wrong.

**Minimal reproduction**
A short Flask app snippet that reproduces the issue — the smaller the
better. Include the exact `Aegis(...)` / `aegis.add_policy(...)` /
`aegis.field(...)` calls involved.

```python
# your minimal repro here
```

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened — include the exact error message, status code,
or response body if relevant.

**Environment**
- Flask-Aegis version: (`python -c "import flask_aegis; print(flask_aegis.__version__)"`)
- Flask version:
- Python version:
- OS:

**Additional context**
Anything else that might be relevant — output of `flask aegis config`,
`flask aegis routes`, or `flask aegis audit` if applicable.
