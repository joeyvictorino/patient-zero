# Field notes: what happened when `pz check` met code it had never seen

`pz check` was written against a sample app and this repository. That says little about how it behaves on real code, so on 2026-11-22 it was run on 13 public Python packages downloaded from PyPI: AI coding assistants, LLM gateways and frameworks, chat and research tools, a web framework and two health data libraries. 8,742 files in all. None is a health app and none was chosen for having problems. They are not named here, because the point is the tool's behavior and not anyone's code.

## First run: 541 findings, and a lot of them wrong

| What it flagged | Why it was wrong | Fix |
| --- | --- | --- |
| `add_scrollbars=False` as an error reporting service | "sc**rollbar**" contains "rollbar" | Word boundaries on the pattern |
| `"analytics.jsonl"` as an analytics tool | It matched `analytics.js` | Boundary after `.js` |
| A folder name, `Flask-AppBuilder-Skeleton-AddOn-master`, as an API key | "Fla**sk-**AppBuilder..." looks like `sk-` plus 32 characters | The key must start at a word boundary and contain a digit |
| `AKIAIOSFODNN7EXAMPLE` as a leaked AWS key | It is the example key from AWS's own documentation | Lines that say example, placeholder or redacted are skipped |
| A form field's placeholder text as a private key | It was `-----BEGIN RSA PRIVATE KEY-----\n...` | Same |
| `"replicate": replicate_models` as a call to Replicate | A dictionary key | Imports and hosts only |
| Commented-out lines | A comment runs nothing | Comment lines are skipped, except for secrets: a key in a comment still leaks |
| A table called `if` with no row level security | Prose in a SQL comment read as `create table if` | Reserved words are not table names |
| 291 "records audio" findings in one package | Every line mentioning a speech-to-text vendor | Vendors are reported once, as data recipients; the audio rule now matches capture and transcription calls |
| The same tracker flagged on every line of a file | One finding per line | One finding per rule per file, with a count of further lines |
| An analytics SDK labelled a session recorder | Wrong category | Reclassified; session recording is flagged when it is switched on |

Every row is now a regression test in `tests/test_check.py`.

## After the fixes: 82 findings

Ten of the 13 packages had at least one. By kind:

| Kind | Count | Reading them by hand |
| --- | --- | --- |
| An AI model company receives data, with no register entry | 47 | Right by construction: the package imports that company's SDK or calls its host. Two matched documentation strings. For a library this is expected and not a flaw. |
| Analytics | 18 | The packages do send usage analytics. Some matches are configuration key names in files that are part of that integration. |
| Error reporting | 5 | Four real. One is an example inside a docstring. |
| Audio transcription | 4 | Real transcription calls. |
| Certificate checks off | 3 | Two real (`verify=False` on live requests). One is the text of an error message. |
| Wildcard CORS | 2 | Both real. |
| Committed `.env` with a password | 1 | Real, in a development setup. |
| Database published on every interface | 1 | Real, same development setup. |
| Table without row level security | 1 | True as stated, but the package does not use row level security for isolation, so it is beside the point. |

Of the 35 findings that are not model providers, two are plainly wrong and several more are true and unimportant for a library. No secret was reported, correctly: none of the packages contains one.

Speed: 8,742 files in about 12 seconds on one core.

## What this does and does not show

- It shows the false alarms on ordinary code went from most of the output to a small share, and that what remains is mostly true statements.
- It does **not** measure misses. Nobody planted flaws in these packages, so there is no way to say what the check failed to find. The only measured miss is in the sample app: `examples/vibe-clinic/src/app/api.py` lets any caller read any note, and the check cannot see it.
- These are libraries and developer tools. A health app built on a web framework with a hosted database will hit different rules (browser keys, row level security, trackers on patient pages) that this corpus barely exercised.
- Thirteen packages is a small sample, read by one person.

## What would make this real

A set of consenting, real health apps with known flaws, so that misses can be counted. If you maintain one and are willing to run `pz check . --json` and say what it got wrong, that is the most useful report this project could receive.
