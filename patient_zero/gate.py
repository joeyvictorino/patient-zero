"""PHI gate: off by default, on only with a BAA, closed on any failure.

Covers GATE-1 (default off), GATE-2 (BAA, named approver, audit record)
and GATE-4 (fail closed). Wire `check` or `guard` in front of every code
path that stores, reads or sends PHI.

    gate = PHIGate(lookup=my_baa_lookup, audit=my_audit_log)

    @gate.guard
    def save_patient_note(workspace_id, note): ...
"""
from __future__ import annotations

import functools
from dataclasses import dataclass
from datetime import date
from typing import Callable, Optional


@dataclass(frozen=True)
class BAARecord:
    workspace_id: str
    executed: bool
    approved_by: Optional[str] = None  # named owner who turned PHI on
    expires: Optional[date] = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class PHIAccessDenied(PermissionError):
    pass


class PHIGate:
    def __init__(
        self,
        lookup: Callable[[str], Optional[BAARecord]],
        audit=None,
        today: Callable[[], date] = date.today,
    ):
        self._lookup = lookup
        self._audit = audit
        self._today = today

    def check(self, workspace_id: str) -> Decision:
        try:
            record = self._lookup(workspace_id)
        except Exception as exc:  # GATE-4: an unanswerable check is a denial
            decision = Decision(False, f"gate check failed: {type(exc).__name__}")
        else:
            decision = self._decide(workspace_id, record)
        if not self._record(workspace_id, decision) and decision.allowed:
            # GATE-2 needs an audit record. No record, no PHI.
            decision = Decision(False, "audit log unavailable")
        return decision

    def _decide(self, workspace_id: str, record: Optional[BAARecord]) -> Decision:
        if record is None:
            return Decision(False, "no BAA on file")  # GATE-1
        if record.workspace_id != workspace_id:
            return Decision(False, "BAA record is for a different workspace")
        if not record.executed:
            return Decision(False, "BAA not executed")
        if not record.approved_by:
            return Decision(False, "no named approver")
        if record.expires is not None and record.expires < self._today():
            return Decision(False, "BAA expired")
        return Decision(True, "BAA executed and approved")

    def _record(self, workspace_id: str, decision: Decision) -> bool:
        if self._audit is None:
            return True
        try:
            self._audit.append(
                user="system",
                workspace=workspace_id,
                action="phi_gate.allow" if decision.allowed else "phi_gate.deny",
                obj=workspace_id,
                detail={"reason": decision.reason},
            )
            return True
        except Exception:
            return False

    def require(self, workspace_id: str) -> None:
        decision = self.check(workspace_id)
        if not decision.allowed:
            raise PHIAccessDenied(decision.reason)

    def guard(self, fn):
        """Decorator. The wrapped function's first argument is the workspace id."""

        @functools.wraps(fn)
        def wrapper(workspace_id, *args, **kwargs):
            self.require(workspace_id)
            return fn(workspace_id, *args, **kwargs)

        return wrapper
