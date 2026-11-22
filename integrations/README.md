# Integrations

patient-zero is most useful when it runs without anyone remembering to run it. Each of these runs `pz check`, the zero-setup scan. This repository's own CI runs the GitHub Action, the pre-commit hook and the MCP server (against the official MCP client library) on every push.

## A coding agent (Claude Code, Cursor, any MCP client)

**Model Context Protocol server.** `pz mcp` serves six read-only tools over stdio: `pz_check`, `pz_controls`, `pz_explain`, `pz_scan_text`, `pz_questionnaire`, `pz_status`. Copy [`mcp.json`](mcp.json) into your client's MCP configuration (for Claude Code, `.mcp.json` in the project root), or:

```
claude mcp add patient-zero -- pz mcp
```

Nothing the server offers can edit a project, record a pass or sign anything.

**Claude Code skill.** Copy [`claude-code/skills/patient-zero`](claude-code/skills/patient-zero) to `.claude/skills/patient-zero` in your project (or `~/.claude/skills/` for every project). Claude then runs the check on its own when it works on a health app.

**Any other agent.** Paste [`AGENTS.md`](AGENTS.md) into the instructions file your agent reads.

## GitHub Actions

```yaml
name: patient-zero
on: [push, pull_request]
permissions:
  contents: read
  security-events: write        # only needed with upload-sarif
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: joeyvictorino/patient-zero@main
        with:
          fail-on: high
          upload-sarif: "true"
```

The job summary shows the plain-language result. With `upload-sarif`, findings also appear in the repository's code scanning tab and on pull request lines. Pin to a tag or commit once releases exist.

## pre-commit

```yaml
repos:
  - repo: https://github.com/joeyvictorino/patient-zero
    rev: main
    hooks:
      - id: patient-zero-check
```

## Your own checks

A package can add checks to `pz check` by registering a function under the `patient_zero.checks` entry point group:

```toml
[project.entry-points."patient_zero.checks"]
my-check = "my_package.checks:run"
```

```python
from patient_zero.check import Issue

def run(root, files):
    return [Issue(rule="my-rule", severity="high", control="GATE-3", title="...", why="...", fix="...", file="app.py", line=3)]
```

Rules that are a single regular expression do not need code: add them to `patient_zero/data/check_rules.yaml` and open a pull request.
