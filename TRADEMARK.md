# Using the patient-zero name and badge

The code is MIT licensed: use it, change it, sell things built on it. The **name** and the **badge** are different, because people will read them as a statement about a product's safety. These rules keep that statement true.

"patient-zero" is used as an unregistered mark by the project lead. It has not been registered; whether and where to register it is the project lead's decision.

## What you may say

- "We ran patient-zero" or "Assessed with patient-zero", **with** the date, the level, and a link to the sealed evidence so a reader can verify it.
- The numbers a seal states: how many safeguards are confirmed, how many failed, who signed.
- "Implements the patient-zero specification" for software that passes the conformance vectors for the class it claims (`spec/SPEC.md`, section 6).

## What you may not say

- "patient-zero certified", "patient-zero compliant", "passed patient-zero", "patient-zero approved", or anything else that reads as a verdict. The tool gives no verdict, and no HIPAA certification exists.
- "HIPAA compliant" on the strength of a patient-zero run.
- That the project, its maintainers or its reviewers endorse a product.

## The badge

Generate it with `pz badge --report-url <where the evidence is>`. Then:

1. **It links to the evidence.** The badge must link to a page where the sealed bundle can be downloaded, with a link to a verifier. A badge that links nowhere may not be used.
2. **It is not edited.** Do not change its text or colour, and do not redraw it in green.
3. **It is current.** Replace it when you reseal. Remove it when the seal is more than 12 months old or the product has changed so much that the seal no longer describes it.
4. **It keeps its sentence.** Wherever the badge appears, the line `pz badge` prints goes with it or sits one click away: this is not a certification and does not mean HIPAA compliant.

## Forks and other implementations

Fork the code freely. A fork that changes the controls, the rules for statuses or what the badge says should use a different name for its badge, so that "ran patient-zero" keeps meaning one thing.

## If you see misuse

Open an issue with a link or screenshot. Misuse is first raised with the company privately.
