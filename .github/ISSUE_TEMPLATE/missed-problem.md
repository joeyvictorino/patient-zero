---
name: A probe missed a real problem
about: False negative, with enough detail to turn it into a test
labels: false-negative
---

**Probe and version** (`pz --version`):

**What was actually wrong in the target:**

**What the probe reported** (clean, void, or inconclusive notes):

**The smallest way to reproduce it.** Ideally a change to `patient_zero/demo/leaky_clinic.py` that makes the demo app wrong in the same way.
