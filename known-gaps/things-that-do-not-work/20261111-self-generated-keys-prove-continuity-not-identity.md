Severity: LOW
Gap-Class: weak

# A seal proves the same key signed, not who holds the key

`pz keygen` makes a key with no link to a person or organization. A verifier learns that successive seals share a signer, nothing more.

What would close this: a documented way to publish and pin the public key, or support for signing with an existing identity such as an SSH or Sigstore key.
