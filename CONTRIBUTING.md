# Contributing

The most useful contributions are listed in `known-gaps/things-that-do-not-work/`. Each file says what would close it.

## Which file do I edit?

| I want to | Edit |
| --- | --- |
| Change a control's wording, level or mapping | `patient_zero/data/controls.yaml`, then regenerate the docs (below) |
| Change a likelihood or cost | `patient_zero/data/belief.yaml`, and say in the pull request what the number is based on |
| Add a probe | `patient_zero/probes/<name>.py` with a `CONTROLS` list and a `run` function, register it in `patient_zero/coverage.py` and `patient_zero/cli.py`, add coverage and detection entries to `belief.yaml` |
| Make the demo app wrong in a new way | `patient_zero/demo/leaky_clinic.py` |
| Add reference code for a control | a module under `patient_zero/`, registered in `patient_zero/coverage.py` |
| Record a limit you found | a new file in `known-gaps/things-that-do-not-work/` |

## Rules for a probe

1. It fails on the vulnerable build of the demo app and is clean on the patched build. Both are tests.
2. It counts only checks that could have found a problem (`result.tick`). A run with none is void.
3. A network finding is reported only after it reproduces.
4. It records nothing secret. Tokens never enter an evidence file.
5. It refuses to run without the authorization fields in the target file, unless it only reads local files.

## Before you open a pull request

```
pip install -e ".[dev]" ruff
ruff check .
pytest -q
pz coverage --markdown > docs/COVERAGE.md
pz controls --markdown > docs/PROFILE.md
```

A test fails if the generated documents are out of date.

## Known gaps

A gap file starts with two header lines, then a title and a description:

```
Severity: HIGH | MEDIUM | LOW
Gap-Class: missing | wrong | weak | unverified
```

When a gap is fixed, move its file to `known-gaps/things-that-now-work/` and say what changed.
