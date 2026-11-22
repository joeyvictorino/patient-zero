Severity: MEDIUM
Gap-Class: unverified

# The agent and CI integrations have not been run in the products they target

- `action.yml` has not run on GitHub Actions. Its YAML parses and its shell steps were run by hand.
- `.pre-commit-hooks.yaml` has not been installed through pre-commit.
- `pz mcp` is tested by speaking JSON-RPC to it directly. It has not been connected to Claude Code, Cursor or another MCP client, and it implements only the tools part of the protocol at version 2024-11-05.
- The Claude Code skill has not been evaluated: nobody has measured whether an agent given it runs the check when it should, or obeys its rules.
- The verify page was tested in headless Chromium only. Firefox and Safari are untested.

What would close this: a run of each in its real host, with the result recorded here, and an evaluation set for the skill.
