Severity: MEDIUM
Gap-Class: missing

# The profile has no dedicated tenant isolation control

Cross-tenant access to ordinary API data is the most common serious finding in multi-tenant apps, and the profile only covers it indirectly: GATE-3 (enclave separation) and MEM-1 (memory scope). The isolation, stack and rls probes all report against GATE-3 for lack of a better home.

What would close this: a new control in the next profile version, with the three probes remapped.
