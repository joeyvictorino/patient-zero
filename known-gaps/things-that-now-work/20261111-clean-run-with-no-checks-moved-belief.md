Severity: HIGH
Gap-Class: wrong

# A run that tested nothing used to count as clean

A probe whose setup failed reported no findings, and that lifted the control to partial and nudged belief upward. Fixed: such a run is now void. It changes no status, moves no belief and settles no prediction.
