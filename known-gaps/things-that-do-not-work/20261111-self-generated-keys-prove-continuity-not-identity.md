Severity: LOW
Gap-Class: weak

# Signer identity rests on a domain and nothing stronger

`pz keygen` makes a key with no link to a person or organization. Since 2026-11-22 a signer can name a domain (`pz seal --domain`), publish the key there (`pz identity`), and a verifier can check it (`pz verify --check-domain`, or the button on the verify page). An independent party can co-sign (`pz cosign`).

What is still weak:

- The check proves control of a web server at that domain at the moment of checking. A compromised site, a lapsed domain or a look-alike domain defeats it. The verifier does not pin a key between visits or keep a history.
- Nothing vets a co-signer. "independent-assessor" is a role the co-signer gives themselves.
- There is no revocation beyond marking a key `retired` in the same file an attacker would control.
- The browser check needs the domain to allow cross-origin reads; otherwise the buyer compares the key by eye.

What would close this: a public, append-only log of seals and keys (in the manner of certificate transparency or Sigstore), and a directory of assessors the project has some basis to list.
