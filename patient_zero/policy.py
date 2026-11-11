"""Agent action gate: the agent proposes, a deterministic policy decides.

    agent proposes  ->  policy evaluates  ->  only allowed fields cross

Never: agent decides -> protected data crosses.

Nothing here asks a model for its opinion. Every check is a set comparison or
a clock comparison, so the same proposal always gets the same answer and the
answer can be tested. Covers AGENT-2 (an agent never exceeds its user, and is
read-only unless granted more), AGENT-3 (disclosing or destructive actions
need a human confirmation bound to the exact recipient and content), AGENT-6
(short-lived, single-use proposals) and AGENT-7 (only allowlisted fields leave).

    gate = ActionGate(policy, workspace="ws_clinic", user_capabilities=lookup, audit=log)
    decision = gate.evaluate(proposal)
    if decision.allowed:
        safe = gate.release(proposal, raw_result)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, FrozenSet, Iterable, Optional, Set, Tuple


def content_digest(recipient: str, content: str) -> str:
    """What a human confirmation is bound to: this recipient and this exact content."""
    return hashlib.sha256(f"{len(recipient)}:{recipient}{content}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Policy:
    version: str
    allowed_capabilities: FrozenSet[str]
    allowed_outputs: FrozenSet[str]
    write_capabilities: FrozenSet[str] = frozenset()
    confirm_actions: FrozenSet[str] = frozenset()
    dangerous_combinations: Tuple[FrozenSet[str], ...] = ()
    max_ttl: timedelta = timedelta(minutes=15)


@dataclass(frozen=True)
class Confirmation:
    by: str        # the human who confirmed
    digest: str    # content_digest(recipient, content) as shown to them


@dataclass(frozen=True)
class Proposal:
    agent: str
    user: str                      # the human the agent acts for
    workspace: str
    action: str
    capabilities: FrozenSet[str]
    outputs: FrozenSet[str]
    nonce: str
    expires_at: str                # ISO 8601 with offset
    policy_version: str
    recipient: str = ""
    content: str = ""
    confirmation: Optional[Confirmation] = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("expiry needs a UTC offset")
    return parsed


@dataclass
class ActionGate:
    policy: Policy
    workspace: str
    user_capabilities: Callable[[str], Iterable[str]]
    agent_write_grants: Callable[[str], Iterable[str]] = lambda agent: ()
    audit: Any = None
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    _used_nonces: Set[str] = field(default_factory=set)

    def evaluate(self, proposal: Proposal) -> Decision:
        try:
            decision = self._decide(proposal)
        except Exception as exc:  # an unanswerable check is a denial
            decision = Decision(False, f"GATE_CHECK_FAILED:{type(exc).__name__}")
        if not self._record(proposal, decision) and decision.allowed:
            decision = Decision(False, "AUDIT_UNAVAILABLE")
        if decision.allowed:
            self._used_nonces.add(proposal.nonce)
        return decision

    def _decide(self, p: Proposal) -> Decision:
        policy = self.policy
        if p.workspace != self.workspace:
            return Decision(False, "WORKSPACE_MISMATCH")
        if p.policy_version != policy.version:
            return Decision(False, "POLICY_VERSION_MISMATCH")
        if not p.nonce:
            return Decision(False, "NONCE_MISSING")
        if p.nonce in self._used_nonces:
            return Decision(False, "REPLAY_DETECTED")
        if not p.expires_at:
            return Decision(False, "EXPIRY_MISSING")
        try:
            expiry = _parse_time(p.expires_at)
        except (ValueError, TypeError):
            return Decision(False, "EXPIRY_INVALID")
        now = self.now()
        if expiry <= now:
            return Decision(False, "PROPOSAL_EXPIRED")
        if expiry - now > policy.max_ttl:
            return Decision(False, "TTL_TOO_LONG")

        requested = set(p.capabilities)
        for combination in policy.dangerous_combinations:
            if combination <= requested:
                return Decision(False, "DANGEROUS_COMBINATION:" + "+".join(sorted(combination)))
        unknown = requested - policy.allowed_capabilities
        if unknown:
            return Decision(False, "CAPABILITY_NOT_ALLOWED:" + ",".join(sorted(unknown)))
        beyond_user = requested - set(self.user_capabilities(p.user))
        if beyond_user:
            return Decision(False, "EXCEEDS_USER:" + ",".join(sorted(beyond_user)))
        ungranted = (requested & policy.write_capabilities) - set(self.agent_write_grants(p.agent))
        if ungranted:
            return Decision(False, "WRITE_NOT_GRANTED:" + ",".join(sorted(ungranted)))
        unexpected = set(p.outputs) - policy.allowed_outputs
        if unexpected:
            return Decision(False, "OUTPUT_NOT_ALLOWED:" + ",".join(sorted(unexpected)))

        if p.action in policy.confirm_actions:
            if p.confirmation is None:
                return Decision(False, "CONFIRMATION_REQUIRED")
            if p.confirmation.by == p.agent or not p.confirmation.by:
                return Decision(False, "CONFIRMATION_NOT_HUMAN")
            if p.confirmation.digest != content_digest(p.recipient, p.content):
                return Decision(False, "CONFIRMATION_MISMATCH")
        return Decision(True, "AUTHORIZED")

    def _record(self, p: Proposal, decision: Decision) -> bool:
        if self.audit is None:
            return True
        try:
            self.audit.append(
                user=p.user or "unknown",
                agent=p.agent,
                workspace=self.workspace,
                action="agent_gate.allow" if decision.allowed else "agent_gate.deny",
                obj=p.action,
                detail={"reason": decision.reason, "nonce": p.nonce, "policy_version": self.policy.version},
            )
            return True
        except Exception:
            return False

    def release(self, proposal: Proposal, result: Dict[str, Any]) -> Dict[str, Any]:
        """Drop every field the proposal did not declare and the policy does not allow."""
        allowed = set(proposal.outputs) & self.policy.allowed_outputs
        return {key: value for key, value in result.items() if key in allowed}
