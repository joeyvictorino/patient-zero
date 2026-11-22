Severity: LOW
Gap-Class: unverified

# The integrations run in CI, but not yet inside the products people use them from

Since 2026-11-22 a CI job runs each integration in a real host on every push:

- the GitHub Action runs on GitHub Actions, once on clean code (must pass) and once on the sample app (must fail)
- `pz mcp` is driven by the official MCP client library: handshake, tool list, tool calls, an error case
- the pre-commit hook is installed and run by pre-commit, on a clean commit and on a bad one

What is still untested:

- `pz mcp` has not been connected to Claude Code, Cursor or another agent host by a person. The client library speaks the same protocol, but hosts differ in configuration and in how they show tool results. The server implements only the tools part of the protocol, at version 2024-11-05.
- The Claude Code skill has not been evaluated: nobody has measured whether an agent given it runs the check when it should, or obeys its rules.
- SARIF upload to GitHub code scanning (`upload-sarif: "true"`) has not been run. The SARIF file is produced and its structure is tested.
- The verify page was tested in headless Chromium only. Firefox and Safari are untested.

What would close this: one person connecting the MCP server in an agent host and saying what happened, an evaluation set for the skill, one run with SARIF upload on, and the verify page opened in the other two browsers.
