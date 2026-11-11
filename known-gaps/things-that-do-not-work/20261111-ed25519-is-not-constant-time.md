Severity: LOW
Gap-Class: weak

# The Ed25519 signer is not constant-time

The signer is pure Python on big integers. Verification is unaffected. Signing on a machine where an attacker can measure timing could leak key material.

What would close this: optional use of an audited library or an OS key service when one is installed, keeping the pure Python path for verification.
