Severity: MEDIUM
Gap-Class: missing

# Most controls have no automated test

See `docs/COVERAGE.md` for the generated list. Controls with no probe rely entirely on a person's attestation. Among them: MFA enforcement, key management, deletion of derived memory, confirmation gates on a live system, and connector identity.

What would close this: probes, one control at a time. Each needs a test that fails on a deliberately broken build of the demo app.
