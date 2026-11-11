from datetime import datetime, timedelta, timezone

import pytest

from patient_zero.auditlog import AuditLog, verify
from patient_zero.policy import ActionGate, Confirmation, Policy, Proposal, content_digest

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
POLICY = Policy(
    version="p1",
    allowed_capabilities=frozenset({"record.read", "email.send", "http.external"}),
    allowed_outputs=frozenset({"count", "next_visit"}),
    write_capabilities=frozenset({"email.send"}),
    confirm_actions=frozenset({"email.send"}),
    dangerous_combinations=(frozenset({"record.read", "http.external"}),),
)


def gate(**kw):
    defaults = dict(user_capabilities=lambda user: {"record.read", "email.send", "http.external"},
                    agent_write_grants=lambda agent: {"email.send"}, now=lambda: NOW)
    defaults.update(kw)
    return ActionGate(POLICY, workspace="ws1", **defaults)


def proposal(**kw):
    base = dict(agent="bot", user="dr.a", workspace="ws1", action="record.summarize", capabilities=frozenset({"record.read"}),
                outputs=frozenset({"count"}), nonce="n1", expires_at=(NOW + timedelta(minutes=5)).isoformat(), policy_version="p1")
    base.update(kw)
    return Proposal(**base)


def test_plain_read_is_authorized_once():
    g = gate()
    assert g.evaluate(proposal()).reason == "AUTHORIZED"
    assert g.evaluate(proposal()).reason == "REPLAY_DETECTED"
    assert g.evaluate(proposal(nonce="n2")).allowed


def test_a_denied_proposal_does_not_burn_its_nonce():
    g = gate()
    assert not g.evaluate(proposal(workspace="other")).allowed
    assert g.evaluate(proposal()).allowed


@pytest.mark.parametrize("change,reason", [
    (dict(workspace="ws2"), "WORKSPACE_MISMATCH"),
    (dict(policy_version="p0"), "POLICY_VERSION_MISMATCH"),
    (dict(nonce=""), "NONCE_MISSING"),
    (dict(expires_at=""), "EXPIRY_MISSING"),
    (dict(expires_at="tomorrow"), "EXPIRY_INVALID"),
    (dict(expires_at="2026-11-11T12:05:00"), "EXPIRY_INVALID"),  # no offset
    (dict(expires_at=(NOW - timedelta(seconds=1)).isoformat()), "PROPOSAL_EXPIRED"),
    (dict(expires_at=(NOW + timedelta(hours=2)).isoformat()), "TTL_TOO_LONG"),
    (dict(capabilities=frozenset({"record.read", "http.external"})), "DANGEROUS_COMBINATION:http.external+record.read"),
    (dict(capabilities=frozenset({"shell.exec"})), "CAPABILITY_NOT_ALLOWED:shell.exec"),
    (dict(outputs=frozenset({"count", "note_text"})), "OUTPUT_NOT_ALLOWED:note_text"),
])
def test_denials(change, reason):
    decision = gate().evaluate(proposal(**change))
    assert not decision.allowed and decision.reason == reason


def test_agent_never_exceeds_its_user():
    g = gate(user_capabilities=lambda user: {"record.read"})
    d = g.evaluate(proposal(action="x", capabilities=frozenset({"http.external"})))
    assert d.reason == "EXCEEDS_USER:http.external"


def test_read_only_unless_write_is_granted_to_the_agent():
    g = gate(agent_write_grants=lambda agent: set())
    d = g.evaluate(proposal(action="email.draft", capabilities=frozenset({"email.send"})))
    assert d.reason == "WRITE_NOT_GRANTED:email.send"


def test_disclosure_needs_a_human_confirmation_bound_to_recipient_and_content():
    send = dict(action="email.send", capabilities=frozenset({"email.send"}), recipient="pat@example.com", content="Your visit is at 3pm")
    good = Confirmation(by="dr.a", digest=content_digest("pat@example.com", "Your visit is at 3pm"))
    g = gate()
    assert g.evaluate(proposal(**send)).reason == "CONFIRMATION_REQUIRED"
    assert g.evaluate(proposal(**send, confirmation=Confirmation("bot", good.digest))).reason == "CONFIRMATION_NOT_HUMAN"
    assert g.evaluate(proposal(**dict(send, recipient="attacker@example.com"), confirmation=good)).reason == "CONFIRMATION_MISMATCH"
    assert g.evaluate(proposal(**dict(send, content="Your visit is at 3pm. Also here are the lab results"),
                               confirmation=good)).reason == "CONFIRMATION_MISMATCH"
    assert g.evaluate(proposal(**send, confirmation=good)).allowed


def test_content_digest_does_not_confuse_recipient_and_content():
    assert content_digest("ab", "c") != content_digest("a", "bc")


def test_fails_closed_when_a_lookup_or_the_audit_log_breaks():
    def boom(user):
        raise ConnectionError("directory down")

    assert gate(user_capabilities=boom).evaluate(proposal()).reason == "GATE_CHECK_FAILED:ConnectionError"

    class BrokenAudit:
        def append(self, **_):
            raise OSError("disk full")

    g = gate(audit=BrokenAudit())
    assert g.evaluate(proposal()).reason == "AUDIT_UNAVAILABLE"
    g.audit = None
    assert g.evaluate(proposal()).allowed  # the refused attempt did not burn the nonce


def test_release_lets_only_declared_and_allowed_fields_cross():
    g = gate()
    p = proposal(outputs=frozenset({"count"}))
    raw = {"count": 3, "next_visit": "2026-12-01", "note_text": "full note", "ssn": "000-00-0000"}
    assert g.release(p, raw) == {"count": 3}


def test_every_decision_lands_in_the_audit_log_with_the_agent_named(tmp_path):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    g = gate(audit=log)
    g.evaluate(proposal())
    g.evaluate(proposal())
    import json

    rows = [json.loads(line) for line in open(log.path)]
    assert [r["action"] for r in rows] == ["agent_gate.allow", "agent_gate.deny"]
    assert all(r["agent"] == "bot" and r["user"] == "dr.a" for r in rows)
    assert rows[1]["detail"]["reason"] == "REPLAY_DETECTED"
    assert verify(log.path).ok
