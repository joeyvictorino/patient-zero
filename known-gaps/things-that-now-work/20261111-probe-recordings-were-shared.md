Severity: MEDIUM
Gap-Class: wrong

# Two probe runs on one target shared a recording

Running a second probe overwrote the first result's recorded exchanges, so replay of the first failed. Fixed: each run gets its own list.
