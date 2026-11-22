Severity: MEDIUM
Gap-Class: weak

# `pz check` matches text patterns and cannot see the mistakes that matter most

`pz check` reads source files line by line against `patient_zero/data/check_rules.yaml`. It does not parse code, follow data flow or run anything.

- It misses anything not written the way a rule expects: a key assembled from parts, a tracker loaded through a tag manager, a model called through a proxy or a provider not on the list.
- It flags things that are fine: a tracker used only on a marketing page, a log line whose variable is named `patient_id`, the word "whisper" in a comment.
- It cannot see access control at all. Whether one clinic can read another's records is the commonest serious flaw, and only the isolation probe against a running copy tests it.
- The provider and tracker lists were written from the author's knowledge in November 2026 and will age.
- The model-provider finding does not know which providers will sign a Business Associate Agreement, or on which plans.
- It has been run against small sample projects and this repository, not against a body of real applications. Its false positive and false negative rates are unknown.

What would close this: a corpus of real, consenting projects with known flaws to measure against; parsing for the two or three languages that matter most; and rules contributed by people who review these apps for a living.
