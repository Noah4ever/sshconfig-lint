---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

---
name: Bug report
about: Report a problem with sshconfig-lint
title: "bug: "
labels: bug
---

## What happened
Describe the problem.

## How to reproduce
1.
2.
3.

If possible, include a minimal `ssh_config` snippet that triggers it (redact hostnames).

## What you expected
What should have happened instead?

## Output
Run with text output and paste it here:

```bash
sshconfig-lint --version
sshconfig-lint --config path/to/config
````

If you can, also paste JSON output:

```bash
sshconfig-lint --format json --config path/to/config
```

## Environment

* OS:
* Install method: (cargo / AUR / Homebrew / binary)
* Version: (from `sshconfig-lint --version`)

## Extra context

Anything else that might help.
