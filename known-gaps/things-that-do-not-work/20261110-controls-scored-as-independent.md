Severity: HIGH
Gap-Class: wrong

# Controls are scored as if independent

P(every control holds) multiplies per-control beliefs. Real controls share causes: one weak engineering practice breaks several at once, and one strong one protects several. The product is therefore wrong in both directions. `pz fragile` exposes shared evidence sources but does not correct the number.

What would close this: a dependency model between controls, or dropping the product in favor of expected-broken alone.
