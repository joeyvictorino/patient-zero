Severity: HIGH
Gap-Class: wrong

# The agent leak test could pass on a canary nobody could retrieve

If the canary was never stored, or the agent could not retrieve it even for its owner, silence toward the other tenant looked like isolation. Fixed: the owner's agent must produce the canary first, or the test is void for that canary.
