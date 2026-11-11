"""Static probe: Docker Compose files that publish an AI stack's insides (GATE-3).

Needs no running target and no target file: `pz probe stack --path .`

This is a small port of the exposure rules from tasia, a static gate for
self-hosted AI stacks by the same author. tasia has the full rule set with
file:line findings and a hardening pack: https://github.com/joeyvictorino/tasia
"""
from __future__ import annotations

import glob
import os
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .common import ProbeRefused, ProbeResult

CONTROLS = ["GATE-3"]

IMAGE_KEYWORDS = [
    ("inference API", ["ollama", "vllm", "llama.cpp", "llamacpp", "lmstudio", "lm-studio"]),
    ("model UI", ["open-webui", "openwebui", "gradio"]),
    ("vector database", ["qdrant", "chroma", "weaviate", "milvus"]),
    ("data store", ["redis", "valkey", "postgres", "pgvector"]),
]
PORT_CATEGORY = {11434: "inference API", 1234: "inference API", 7860: "model UI", 6333: "vector database",
                 19530: "vector database", 6379: "data store", 5432: "data store"}
_LOCAL = {"127.0.0.1", "localhost", "::1", "[::1]"}


def classify(image: str, host_port: int = 0) -> Optional[str]:
    img = (image or "").lower()
    for category, needles in IMAGE_KEYWORDS:
        if any(n in img for n in needles):
            return category
    return PORT_CATEGORY.get(host_port)


def parse_port(port: Any) -> Tuple[str, int]:
    """Return (host ip or '' for all interfaces, host port or 0 when not published)."""
    if isinstance(port, dict):
        published = port.get("published")
        return str(port.get("host_ip") or ""), int(published) if str(published or "").isdigit() else 0
    raw = str(port).strip().strip("\"'").split("/")[0]
    if raw.startswith("["):  # [::1]:8080:80
        ip, _, rest = raw.partition("]:")
        parts = rest.split(":")
        return ip + "]", int(parts[0]) if len(parts) >= 2 and parts[0].isdigit() else 0
    parts = raw.split(":")
    if len(parts) == 1:
        return "", 0  # container port only; Docker picks a random host port
    host = parts[-2].split("-")[0]
    return (parts[0] if len(parts) >= 3 else ""), int(host) if host.isdigit() else 0


def _environment(service: Dict[str, Any]) -> Dict[str, str]:
    env = service.get("environment") or {}
    if isinstance(env, list):
        pairs = (str(item).partition("=") for item in env)
        return {k.strip(): v.strip() for k, _, v in pairs}
    return {str(k): "" if v is None else str(v) for k, v in env.items()}


def compose_files(path: str) -> List[str]:
    if os.path.isfile(path):
        return [path]
    found = []
    for pattern in ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml"):
        found += glob.glob(os.path.join(path, pattern))
    return sorted(set(found))


def run(path: str) -> ProbeResult:
    files = compose_files(path)
    if not files:
        raise ProbeRefused(f"no Docker Compose file found at {path}")
    result = ProbeResult("stack", CONTROLS, os.path.abspath(path))
    for file in files:
        name = os.path.relpath(file, path) if os.path.isdir(path) else os.path.basename(file)
        try:
            with open(file, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            services = doc.get("services") or {}
            if not isinstance(services, dict):
                raise ValueError("services is not a mapping")
        except (yaml.YAMLError, ValueError, AttributeError) as exc:  # fail closed
            raise ProbeRefused(f"cannot parse {name}: {exc}") from exc
        for svc_name, service in services.items():
            if not isinstance(service, dict):
                continue
            result.tick("GATE-3")
            image = str(service.get("image", ""))
            where = f"{name} service '{svc_name}'"
            if str(service.get("network_mode", "")).lower() == "host" and classify(image):
                result.add("GATE-3", "high", f"{classify(image)} on the host network", where)
            for port in service.get("ports") or []:
                ip, host_port = parse_port(port)
                category = classify(image, host_port)
                if host_port and category and ip not in _LOCAL:
                    result.add("GATE-3", "high", f"{category} published to all interfaces", f"{where} port {host_port}")
            if service.get("privileged") is True:
                result.add("GATE-3", "high", "privileged container", where)
            for volume in service.get("volumes") or []:
                source = volume.get("source", "") if isinstance(volume, dict) else str(volume).split(":")[0]
                if str(source).rstrip("/").endswith("docker.sock"):
                    result.add("GATE-3", "high", "Docker socket mounted into a container", where)
            for key, value in _environment(service).items():
                if ("ORIGIN" in key.upper() or "CORS" in key.upper()) and value.strip().strip("\"'") == "*":
                    result.add("GATE-3", "medium", f"wildcard CORS ({key}=*)", where)
    return result
