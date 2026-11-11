from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml


class ProbeRefused(Exception):
    """The target file does not meet the conditions for testing."""


@dataclass
class Finding:
    control: str
    severity: str  # critical | high | medium | low
    title: str
    detail: str = ""


@dataclass
class ProbeResult:
    probe: str
    controls: List[str]
    target: str
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    checks: int = 0
    checks_for: Dict[str, int] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    inconclusive: List[str] = field(default_factory=list)
    authorization_ref: Optional[str] = None

    @property
    def clean(self) -> bool:
        return not self.findings

    def tick(self, *controls: str) -> None:
        """Count one check, and credit it to the controls it can speak to."""
        self.checks += 1
        for control in controls:
            self.checks_for[control] = self.checks_for.get(control, 0) + 1

    def add(self, control: str, severity: str, title: str, detail: str = "") -> None:
        self.findings.append(Finding(control, severity, title, detail))

    def grouped(self) -> List[str]:
        """Findings as display lines, with repeats collapsed."""
        counts: Dict[tuple, int] = {}
        for f in self.findings:
            key = (f.severity.upper(), f.control, f.title)
            counts[key] = counts.get(key, 0) + 1
        return [f"[{sev}] {control}: {title}" + (f" (x{n})" if n > 1 else "") for (sev, control, title), n in counts.items()]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["clean"] = self.clean
        return data


@dataclass
class Response:
    status: int
    text: str
    headers: Dict[str, str]

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def load_target(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        target = yaml.safe_load(fh) or {}
    if target.get("authorized") is not True:
        raise ProbeRefused(
            "target file must set `authorized: true`. Only test systems you own or have written permission to test."
        )
    if target.get("synthetic_data_only") is not True:
        raise ProbeRefused(
            "target file must set `synthetic_data_only: true`. Probes are for test tenants with synthetic data, never real PHI."
        )
    if not target.get("authorization_ref"):
        raise ProbeRefused("target file must set `authorization_ref` (the rules of engagement or ticket that authorizes this test).")
    base = str(target.get("base_url", ""))
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ProbeRefused("target file needs a `base_url` such as https://staging.example.com")
    target["base_url"] = base.rstrip("/")
    target["_dir"] = os.path.dirname(os.path.abspath(path))
    return target


def resolve_token(value: Optional[str]) -> Optional[str]:
    """Tokens may be written as `env:NAME` so secrets stay out of the file."""
    if value is None:
        return None
    value = str(value)
    if value.startswith("env:"):
        name = value[4:]
        if name not in os.environ:
            raise ProbeRefused(f"environment variable {name} is not set")
        return os.environ[name]
    return value


def tenant_token(target: Dict[str, Any], name: str) -> str:
    try:
        return resolve_token(target["tenants"][name]["token"])  # type: ignore[return-value]
    except (KeyError, TypeError):
        raise ProbeRefused(f"target file needs tenants.{name}.token")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # stay on the declared target
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def request(
    target: Dict[str, Any],
    method: str,
    path: str,
    token: Optional[str] = None,
    body: Any = None,
    timeout: float = 20.0,
) -> Response:
    if not path.startswith("/") or path.startswith("//"):
        raise ProbeRefused(f"path must be relative to base_url and start with '/': {path!r}")
    url = target["base_url"] + path
    headers = {"Accept": "application/json", "User-Agent": "patient-zero-probe/0.1"}
    if token:
        header = target.get("auth_header", "Authorization")
        scheme = target.get("auth_scheme", "Bearer")
        headers[header] = f"{scheme} {token}".strip()
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return Response(resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers))
    except urllib.error.HTTPError as err:
        return Response(err.code, err.read().decode("utf-8", "replace"), dict(err.headers or {}))


def fill(template: Any, **values: str) -> Any:
    """Replace {name} placeholders inside any string of a JSON-like structure."""
    if isinstance(template, str):
        out = template
        for key, value in values.items():
            out = out.replace("{" + key + "}", value)
        return out
    if isinstance(template, list):
        return [fill(item, **values) for item in template]
    if isinstance(template, dict):
        return {k: fill(v, **values) for k, v in template.items()}
    return template


def write_evidence(result: ProbeResult, directory: str = "evidence") -> str:
    """TEST-4: dated, hashed evidence an assessor can file."""
    os.makedirs(directory, exist_ok=True)
    payload = result.to_dict()
    blob = json.dumps(payload, indent=2, sort_keys=True)
    payload_hash = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = os.path.join(directory, f"{result.probe}-{stamp}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"sha256": payload_hash, "result": payload}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path
