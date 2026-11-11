"""Subprocessor register and egress allowlist (TRUST-1, TRUST-2, TRUST-3).

The register is a YAML file you own:

    endpoints:
      - host: api.model-vendor.example
        purpose: LLM inference
        baa: true
        training_on_phi: prohibited     # prohibited | permitted | unknown
        retention: 0 days
      - host: "*.storage.example"
        baa: true
        training_on_phi: prohibited
        retention: per contract

`check_hosts` compares hosts you observed leaving the PHI enclave (from a
proxy log, flow log or packet capture) against it. `EgressGuard` is the
same rule as an in-process check; real enforcement belongs at the network.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Iterable, List, Optional

import yaml


@dataclass(frozen=True)
class Endpoint:
    host: str
    baa: bool = False
    training_on_phi: str = "unknown"
    retention: Optional[str] = None
    purpose: Optional[str] = None

    def approved(self) -> bool:
        return self.baa and self.training_on_phi == "prohibited" and bool(self.retention)

    def problems(self) -> List[str]:
        out = []
        if not self.baa:
            out.append("no BAA")
        if self.training_on_phi != "prohibited":
            out.append(f"training on PHI is {self.training_on_phi}")
        if not self.retention:
            out.append("retention not documented")
        return out


@dataclass(frozen=True)
class Violation:
    host: str
    reason: str


def load_register(path: str) -> List[Endpoint]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    endpoints = []
    for item in raw.get("endpoints", []):
        endpoints.append(
            Endpoint(
                host=str(item["host"]).lower().strip(),
                baa=bool(item.get("baa", False)),
                training_on_phi=str(item.get("training_on_phi", "unknown")),
                retention=(str(item["retention"]) if item.get("retention") is not None else None),
                purpose=item.get("purpose"),
            )
        )
    return endpoints


def normalize_host(value: str) -> str:
    host = value.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.startswith("["):  # IPv6 literal
        return host.split("]", 1)[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def match(host: str, register: Iterable[Endpoint]) -> Optional[Endpoint]:
    host = normalize_host(host)
    for ep in register:
        if ep.host == host or ("*" in ep.host and fnmatch.fnmatch(host, ep.host)):
            return ep
    return None


def check_hosts(observed: Iterable[str], register: List[Endpoint]) -> List[Violation]:
    violations = []
    for raw in sorted({normalize_host(h) for h in observed if h.strip()}):
        ep = match(raw, register)
        if ep is None:
            violations.append(Violation(raw, "not in the register"))
        elif not ep.approved():
            violations.append(Violation(raw, "; ".join(ep.problems())))
    return violations


class EgressDenied(PermissionError):
    pass


class EgressGuard:
    def __init__(self, register: List[Endpoint]):
        self._register = register

    def require(self, url_or_host: str) -> None:
        ep = match(url_or_host, self._register)
        if ep is None:
            raise EgressDenied(f"{normalize_host(url_or_host)}: not in the register")
        if not ep.approved():
            raise EgressDenied(f"{ep.host}: " + "; ".join(ep.problems()))
