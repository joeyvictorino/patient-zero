"""Probes that read files instead of calling the target: egress (TRUST-2) and log integrity (LOG-2)."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from .. import auditlog, egress
from .common import ProbeRefused, ProbeResult


def _resolve(target: Dict[str, Any], path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(target.get("_dir", "."), path)


def run_egress(target: Dict[str, Any]) -> ProbeResult:
    """Compare hosts observed leaving the PHI enclave against the register.

        egress:
          register: register.yaml
          observed: observed_hosts.txt     # one host or URL per line
    """
    cfg = target.get("egress") or {}
    if not cfg.get("register") or not cfg.get("observed"):
        raise ProbeRefused("target file needs egress.register and egress.observed")
    register = egress.load_register(_resolve(target, cfg["register"]))
    with open(_resolve(target, cfg["observed"]), "r", encoding="utf-8") as fh:
        observed = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    result = ProbeResult("egress", ["TRUST-1", "TRUST-2"], target["base_url"], authorization_ref=target.get("authorization_ref"))
    for _ in set(observed):
        result.tick("TRUST-2")
    for _ in register:
        result.tick("TRUST-1")
    if not observed:
        result.inconclusive.append("observed host list is empty")
    for ep in register:
        if not ep.approved():
            result.add("TRUST-1", "medium", f"Register entry {ep.host} is incomplete", "; ".join(ep.problems()))
    for v in egress.check_hosts(observed, register):
        result.add("TRUST-2", "high", f"PHI enclave reached {v.host}", v.reason)
    return result


def run_log(path: str, expected_head: Optional[str] = None, target_name: str = "local file") -> ProbeResult:
    result = ProbeResult("log", ["LOG-2"], target_name)
    outcome = auditlog.verify(path, expected_head)
    result.checks = outcome.entries
    result.checks_for["LOG-2"] = 1 if (outcome.ok and expected_head) or not outcome.ok else 0
    if not outcome.ok:
        result.add("LOG-2", "critical", "Audit log failed verification", outcome.error or "")
    elif expected_head is None:
        result.inconclusive.append("no anchored head supplied; tail truncation would not be detected")
    return result
