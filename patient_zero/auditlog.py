"""Append-only, hash-chained audit log (LOG-1, LOG-2, AGENT-1).

Each entry carries the hash of the entry before it, so an edit, deletion
or reordering anywhere in the file breaks verification from that point on.

Limits you need to know:
  * Truncating the tail is only detectable if you anchor `head()` somewhere
    the application cannot write (a separate account, a ticket, write-once
    storage). Anchor it on a schedule and pass it to `verify`.
  * One writer per file. Put a lock or a single log service in front of it.
  * File permissions and role separation are yours to set up.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

GENESIS = "0" * 64
_FIELDS = ("seq", "ts", "user", "agent", "workspace", "action", "object", "detail", "prev")


def _digest(entry: Dict[str, Any]) -> str:
    body = {k: entry[k] for k in _FIELDS}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    head: str
    error: Optional[str] = None
    bad_seq: Optional[int] = None


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._seq = 0
        self._head = GENESIS
        if os.path.exists(path):
            result = verify(path)
            if not result.ok:
                raise ValueError(f"refusing to append to a broken log: {result.error}")
            self._seq = result.entries
            self._head = result.head

    def head(self) -> str:
        return self._head

    def append(
        self,
        user: str,
        workspace: str,
        action: str,
        obj: str,
        agent: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not user or not workspace or not action:
            raise ValueError("user, workspace and action are required")
        entry: Dict[str, Any] = {
            "seq": self._seq + 1,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "user": user,
            "agent": agent,  # AGENT-1: the agent is named separately from the human
            "workspace": workspace,
            "action": action,
            "object": obj,
            "detail": detail or {},
            "prev": self._head,
        }
        entry["hash"] = _digest(entry)
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._seq = entry["seq"]
        self._head = entry["hash"]
        return entry


def verify(path: str, expected_head: Optional[str] = None) -> VerifyResult:
    """Walk the chain. Pass `expected_head` (an anchored value) to catch truncation."""
    prev = GENESIS
    count = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, count, prev, f"line {lineno}: not valid JSON", count + 1)
            if any(k not in entry for k in _FIELDS + ("hash",)):
                return VerifyResult(False, count, prev, f"line {lineno}: missing fields", count + 1)
            if entry["seq"] != count + 1:
                return VerifyResult(False, count, prev, f"line {lineno}: sequence gap", count + 1)
            if entry["prev"] != prev:
                return VerifyResult(False, count, prev, f"line {lineno}: chain broken", entry["seq"])
            if _digest(entry) != entry["hash"]:
                return VerifyResult(False, count, prev, f"line {lineno}: entry altered", entry["seq"])
            prev = entry["hash"]
            count += 1
    if expected_head is not None and prev != expected_head:
        return VerifyResult(False, count, prev, "head does not match the anchored value (truncated or replaced)")
    return VerifyResult(True, count, prev)
