"""Restore probe (BASE-4): a backup is unproven until a restore matches checksums.

    pz manifest /data/phi -o before.json          # before the backup
    ... back up, then restore somewhere else ...
    pz probe restore --manifest before.json --path /restore/phi
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from hashlib import blake2b
from typing import Any, Dict

from .common import ProbeRefused, ProbeResult

CONTROLS = ["BASE-4"]


def _digest(path: str) -> str:
    h = blake2b(digest_size=32)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest(root: str) -> Dict[str, Any]:
    if not os.path.isdir(root):
        raise ProbeRefused(f"{root} is not a directory")
    files = {}
    for folder, _, names in os.walk(root):
        for name in names:
            full = os.path.join(folder, name)
            if os.path.isfile(full) and not os.path.islink(full):
                files[os.path.relpath(full, root).replace(os.sep, "/")] = _digest(full)
    return {"schema": "patient-zero-manifest-v1", "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "files": dict(sorted(files.items()))}


def run(manifest_path: str, restored_root: str) -> ProbeResult:
    with open(manifest_path, "r", encoding="utf-8") as fh:
        expected = json.load(fh).get("files") or {}
    result = ProbeResult("restore", CONTROLS, os.path.abspath(restored_root))
    if not expected:
        result.inconclusive.append("manifest lists no files; nothing to verify")
        return result
    actual = manifest(restored_root)["files"]
    result.tick("BASE-4")
    result.checks = len(expected)
    missing = sorted(set(expected) - set(actual))
    changed = sorted(p for p in expected if p in actual and actual[p] != expected[p])
    if missing:
        result.add("BASE-4", "high", f"{len(missing)} file(s) missing from the restore", ", ".join(missing[:5]))
    if changed:
        result.add("BASE-4", "high", f"{len(changed)} restored file(s) differ from the original", ", ".join(changed[:5]))
    extra = len(set(actual) - set(expected))
    if extra:
        result.inconclusive.append(f"{extra} file(s) in the restore are not in the manifest")
    return result
