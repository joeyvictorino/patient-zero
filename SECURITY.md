# Security

## Reporting a vulnerability

Report it privately through GitHub: the repository's **Security** tab, then **Report a vulnerability**. Please do not open a public issue for something exploitable.

What counts here:

- a way to make `pz verify`, `pz verify-proof` or `docs/verify/` accept a seal, proof, bundle or co-signature that was altered or forged
- a way to make a badge or report state something the signed seal does not
- a way for a probe to reach a host outside `authorized_hosts`, or to run without the authorization fields
- a way for scanning a hostile repository with `pz check`, or opening a hostile bundle in the verify page, to run code or send data anywhere
- a secret (token, key) ending up in an evidence file or in output

You should hear back within seven days. There is no bounty. Reporters are credited unless they ask not to be.

## What is already known

The Ed25519 implementation is pure Python and not constant-time (see `known-gaps/`). Sign on a machine you control. Verification is not affected.

## Using the tool responsibly

Probes are for systems you own or have written permission to test, holding synthetic data. If you find a vulnerability in someone else's product while testing with permission, report it to them under the terms of that permission, not here.
