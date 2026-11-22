Severity: LOW
Gap-Class: weak

# The Ed25519 signer is not constant-time

The signer is pure Python on big integers. Verification is unaffected. Signing on a machine where an attacker can measure timing could leak key material.

What would close this: optional use of an audited library or an OS key service when one is installed, keeping the pure Python path for verification.

Fixed 2026-11-22: signing uses the `cryptography` package (OpenSSL) whenever it is installed (`pip install "patient-zero[sign]"`), and `pz keygen` says so when it is not. Both paths give the same signature for the same key and message, and a test checks that. The pure Python signer remains as the fallback, so a machine without the package still signs with code that is not constant-time. Verification stays pure Python: everything it handles is public.
