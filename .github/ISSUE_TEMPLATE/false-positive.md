---
name: A probe reported something that is not a problem
about: False positive, or a finding you think is wrong
labels: false-positive
---

**Probe and version** (`pz --version`):

**What it reported:**

**Why it is wrong:**

**Evidence file.** Attach the JSON from `evidence/` if it holds synthetic data only. Network probes record every exchange, so we can run `pz replay` on it and see exactly what you saw, without access to your system. Remove anything real first.
