"""Cross-tenant access probe (GATE-3, TEST-1).

For every resource that belongs to tenant A, ask for it three ways:
as A (must work, or the test proves nothing), as B, and with no token.
B and anonymous must be refused.

    isolation:
      canary: PZ-CANARY-A-7f3a      # optional; a string that exists only in tenant A's data
      resources:
        - {method: GET, path: /api/workspaces/ws_a/clients}
"""
from __future__ import annotations

from typing import Any, Dict

from .common import ProbeRefused, ProbeResult, request, start, tenant_token

CONTROLS = ["GATE-3", "TEST-1"]


def run(target: Dict[str, Any]) -> ProbeResult:
    cfg = target.get("isolation") or {}
    resources = cfg.get("resources") or []
    if not resources:
        raise ProbeRefused("target file needs isolation.resources")
    canary = cfg.get("canary")
    token_a = tenant_token(target, "a")
    token_b = tenant_token(target, "b")
    result = start("isolation", CONTROLS, target)

    for res in resources:
        method = str(res.get("method", "GET"))
        path = str(res["path"])
        body = res.get("body")
        label = f"{method.upper()} {path}"

        owner = request(target, method, path, token_a, body)
        result.checks += 1  # setup check; proves nothing about isolation
        if not owner.ok:
            result.inconclusive.append(f"{label}: owner request returned {owner.status}; cannot test this route")
            continue
        if canary and canary not in owner.text:
            result.inconclusive.append(f"{label}: canary not present in the owner's response; route tested on status only")

        for who, token in (("another tenant", token_b), ("an anonymous caller", None)):
            other = request(target, method, path, token, body)
            result.tick("GATE-3", "TEST-1")
            leaked = bool(canary) and canary in other.text
            exposed = other.ok and not (canary and canary in owner.text)
            if leaked or exposed:
                # A finding is a theory until it reproduces. Ask again before reporting it.
                again = request(target, method, path, token, body)
                if not ((leaked and canary in again.text) or (exposed and not leaked and again.ok)):
                    result.inconclusive.append(f"{label}: a response to {who} looked wrong once and did not reproduce")
                    continue
            if leaked:
                result.add("GATE-3", "critical", f"{label} returned tenant A's data to {who}",
                           f"status {other.status}; canary found in the response body; reproduced")
            elif other.ok:
                if canary and canary in owner.text:
                    result.inconclusive.append(
                        f"{label}: {who} got {other.status} without the canary; confirm the response holds none of tenant A's data")
                else:
                    result.add("GATE-3", "high", f"{label} answered {who} with {other.status}",
                               "expected 401, 403 or 404 for a resource owned by tenant A; reproduced")
    return result
