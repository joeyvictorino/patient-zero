Severity: MEDIUM
Gap-Class: missing

# A buyer cannot verify a sealed report without the command line

The plain-language summary and questionnaire need no technical staff, but checking a vendor's seal still means installing the tool and running `pz verify`. A practice manager cannot do that.

What would close this: a single web page, served from a file with no upload, that verifies a seal in the browser.

Fixed 2026-11-22: `pz bundle` packs a seal and its files into one file, and `docs/verify/index.html` verifies it in a browser with nothing installed and nothing uploaded. The page is a second implementation of the verifier and passes the same test vectors as the Python one (`node tools/run_vectors.js`). It is not yet hosted anywhere: until the project serves it, a buyer opens the file from a copy of the repository.
