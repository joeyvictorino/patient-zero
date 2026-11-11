"""Replay a probe run from its evidence file, with no network.

Every network probe records each request and response it saw. Replay feeds
that recording back through the same probe logic and checks that the same
findings come out. A reviewer can confirm the findings follow from what the
target actually returned without access to the target, and a result edited by
hand no longer matches its own recording.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from .probes import ReplayMismatch, agent, isolation
from .probes.common import ProbeResult

REPLAYABLE = {"isolation": isolation.run, "agent": agent.run}


def _findings(items: List[Any]) -> List[Tuple[str, str, str]]:
    rows = [(f["control"], f["severity"], f["title"]) if isinstance(f, dict) else (f.control, f.severity, f.title) for f in items]
    return sorted(rows)


def replay(evidence_path: str) -> Tuple[bool, List[str]]:
    """Return (reproduced, differences)."""
    with open(evidence_path, "r", encoding="utf-8") as fh:
        recorded = json.load(fh)["result"]
    probe = recorded["probe"]
    if probe not in REPLAYABLE:
        raise ValueError(f"the {probe} probe reads files, not the network; rerun it on those files instead")
    if not recorded.get("exchanges"):
        raise ValueError("this evidence file has no recorded exchanges (written by an older version)")
    config: Dict[str, Any] = dict(recorded.get("config") or {})
    if recorded.get("params", {}).get("marker"):
        config["_marker"] = recorded["params"]["marker"]
    target = {
        "base_url": recorded["target"],
        "authorization_ref": recorded.get("authorization_ref"),
        "build": recorded.get("build"),
        "tenants": {"a": {"token": "replay-a"}, "b": {"token": "replay-b"}},
        probe: config,
        "_replay": [dict(x) for x in recorded["exchanges"]],
    }
    try:
        again: ProbeResult = REPLAYABLE[probe](target)
    except ReplayMismatch as exc:
        return False, [str(exc)]
    differences = []
    if target["_replay"]:
        differences.append(f"{len(target['_replay'])} recorded exchange(s) were never asked for")
    if _findings(again.findings) != _findings(recorded["findings"]):
        differences.append(f"findings differ: file says {_findings(recorded['findings'])}, recording yields {_findings(again.findings)}")
    if again.checks != recorded["checks"]:
        differences.append(f"check count differs: file says {recorded['checks']}, recording yields {again.checks}")
    if bool(recorded.get("clean")) != again.clean:
        differences.append(f"file says clean={recorded.get('clean')}, recording yields clean={again.clean}")
    return not differences, differences
