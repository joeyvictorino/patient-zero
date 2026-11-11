"""Black-box probes. Each returns a ProbeResult and writes dated evidence.

A probe can fail a control. It cannot pass one on its own: a clean run
moves a control to `partial` and an assessor confirms coverage.
"""
from .common import Finding, ProbeRefused, ProbeResult, ReplayMismatch, load_target, write_evidence  # noqa: F401
