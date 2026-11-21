Severity: HIGH
Gap-Class: unverified

# The CONSENT family and Nevada item NV-6 cite laws nobody has checked against the source

The eight CONSENT controls (patient-facing AI notices, recording consent, AI descriptions for patients, per-patient opt-out, 42 CFR Part 2 records, bias reporting under 45 CFR 92.210, patient rights, de-identification) and NV-6 (recording consent under NRS 200.620 and 200.650) were written from the author's knowledge. Unlike the original HIPAA citations, none of these were checked against eCFR or the statute text.

Specific doubts:

- 45 CFR 164.514(b), 164.520, 164.522, 164.524, 164.526 and 164.528 are cited at family level without confirming that each is the right home.
- 42 CFR Part 2 was substantially amended in 2024. CONSENT-5 does not reflect the details of the amended consent and redisclosure rules.
- 45 CFR 92.210 applies to covered entities that use patient care decision support tools. CONSENT-6 asks the vendor to supply what the customer needs, which is a reading of the rule, not something it requires of vendors.
- State laws on AI in patient communications (for example California AB 3030) and on recording consent differ by state. CONSENT-1 and CONSENT-2 are written to the strictest common case, not to any one statute.
- NV-6 relies on Lane v. Allstate (Nev. 1998) for all-party consent on telephone recordings. That case was not re-read for this overlay.
- None of the CONSENT controls has a probe.

What would close this: a health privacy lawyer checks each citation and the NV-6 reading, corrections are merged, and `hipaa_citations_checked` covers the CONSENT family.
