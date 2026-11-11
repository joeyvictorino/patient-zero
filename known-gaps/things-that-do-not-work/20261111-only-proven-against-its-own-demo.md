Severity: HIGH
Gap-Class: unverified

# Never run against a real product

Every probe has been exercised only against the bundled Leaky Clinic app and unit fixtures. The TLS probe's HTTPS path has never completed a real handshake in testing.

What would close this: assessment of one real staging environment, with the evidence files published.
