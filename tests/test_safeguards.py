import json
from datetime import date

import pytest

from patient_zero import egress, phi
from patient_zero.auditlog import AuditLog, verify
from patient_zero.gate import BAARecord, PHIAccessDenied, PHIGate


# --- gate -----------------------------------------------------------------

def gate_with(records, **kw):
    return PHIGate(lookup=records.get, **kw)


def test_gate_denies_by_default():
    assert not gate_with({}).check("ws1").allowed


def test_gate_allows_executed_and_approved_baa():
    g = gate_with({"ws1": BAARecord("ws1", True, "owner@example.com")})
    assert g.check("ws1").allowed
    assert not g.check("ws2").allowed


@pytest.mark.parametrize(
    "record",
    [
        BAARecord("ws1", False, "owner@example.com"),
        BAARecord("ws1", True, None),
        BAARecord("ws1", True, "owner@example.com", expires=date(2020, 1, 1)),
        BAARecord("other", True, "owner@example.com"),
    ],
)
def test_gate_denies_incomplete_records(record):
    assert not gate_with({"ws1": record}).check("ws1").allowed


def test_gate_fails_closed_when_lookup_breaks():
    def boom(_):
        raise ConnectionError("db down")

    decision = PHIGate(lookup=boom).check("ws1")
    assert not decision.allowed and "ConnectionError" in decision.reason


def test_gate_denies_when_audit_cannot_be_written():
    class BrokenAudit:
        def append(self, **_):
            raise OSError("disk full")

    g = gate_with({"ws1": BAARecord("ws1", True, "o")}, audit=BrokenAudit())
    decision = g.check("ws1")
    assert not decision.allowed and decision.reason == "audit log unavailable"


def test_gate_guard_and_audit_trail(tmp_path):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    g = gate_with({"ws1": BAARecord("ws1", True, "o")}, audit=log)

    @g.guard
    def write(workspace_id, value):
        return value

    assert write("ws1", 7) == 7
    with pytest.raises(PHIAccessDenied):
        write("ws2", 7)
    actions = [json.loads(line)["action"] for line in open(log.path)]
    assert actions == ["phi_gate.allow", "phi_gate.deny"]


# --- audit log --------------------------------------------------------------

def make_log(tmp_path, n=5):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    for i in range(n):
        log.append(user="u1", agent="agent-7", workspace="ws1", action="record.read", obj=f"rec:{i}")
    return log


def test_log_verifies_and_resumes(tmp_path):
    log = make_log(tmp_path)
    assert verify(log.path).ok and verify(log.path).entries == 5
    again = AuditLog(log.path)
    again.append(user="u2", workspace="ws1", action="record.export", obj="rec:1")
    result = verify(log.path)
    assert result.ok and result.entries == 6 and result.head == again.head()


def test_log_detects_edit(tmp_path):
    log = make_log(tmp_path)
    lines = open(log.path).read().splitlines()
    entry = json.loads(lines[2])
    entry["user"] = "someone-else"
    lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    open(log.path, "w").write("\n".join(lines) + "\n")
    result = verify(log.path)
    assert not result.ok and result.bad_seq == 3 and "altered" in result.error


def test_log_detects_deleted_line(tmp_path):
    log = make_log(tmp_path)
    lines = open(log.path).read().splitlines()
    del lines[1]
    open(log.path, "w").write("\n".join(lines) + "\n")
    assert not verify(log.path).ok


def test_log_truncation_needs_anchor(tmp_path):
    log = make_log(tmp_path)
    anchored = log.head()
    lines = open(log.path).read().splitlines()
    open(log.path, "w").write("\n".join(lines[:3]) + "\n")
    assert verify(log.path).ok  # the chain alone cannot see a cut tail
    assert not verify(log.path, expected_head=anchored).ok


def test_log_refuses_to_extend_broken_file(tmp_path):
    log = make_log(tmp_path)
    open(log.path, "a").write("not json\n")
    with pytest.raises(ValueError):
        AuditLog(log.path)


# --- egress -----------------------------------------------------------------

REGISTER = [
    egress.Endpoint("api.model.example", True, "prohibited", "0 days"),
    egress.Endpoint("*.storage.example", True, "prohibited", "30 days"),
    egress.Endpoint("api.nobaa.example", False, "prohibited", "0 days"),
    egress.Endpoint("api.trains.example", True, "permitted", "0 days"),
]


def test_egress_flags_unknown_and_unapproved_hosts():
    observed = [
        "https://api.model.example/v1/messages",
        "bucket.storage.example:443",
        "API.MODEL.EXAMPLE",
        "analytics.tracker.example",
        "api.nobaa.example",
        "api.trains.example",
    ]
    found = {v.host: v.reason for v in egress.check_hosts(observed, REGISTER)}
    assert set(found) == {"analytics.tracker.example", "api.nobaa.example", "api.trains.example"}
    assert found["analytics.tracker.example"] == "not in the register"
    assert "no BAA" in found["api.nobaa.example"]
    assert "training" in found["api.trains.example"]


def test_wildcard_does_not_match_lookalike_domains():
    assert egress.match("bucket.storage.example", REGISTER) is not None
    assert egress.match("storage.example.attacker.test", REGISTER) is None
    assert egress.match("evilstorage.example", REGISTER) is None


def test_egress_guard():
    guard = egress.EgressGuard(REGISTER)
    guard.require("https://api.model.example/v1")
    with pytest.raises(egress.EgressDenied):
        guard.require("https://api.nobaa.example")
    with pytest.raises(egress.EgressDenied):
        guard.require("unknown.example")


# --- phi detector -------------------------------------------------------------

def test_phi_flags_identifiers():
    text = "Patient John, DOB: 01/02/1980, MRN: A1234567, SSN 123-45-6789, call 702-555-0100"
    kinds = {f.kind for f in phi.scan(text)}
    assert {"dob", "mrn", "ssn", "phone"} <= kinds


def test_phi_ignores_ordinary_business_text():
    assert not phi.likely_phi("Email sam@studio.example about the Q3 sponsorship deck, or call 702-555-0100.")


def test_phi_redact():
    out = phi.redact("Patient SSN 123-45-6789 and DOB: 1/2/1980.")
    assert "123-45-6789" not in out and "[SSN]" in out and "[DOB]" in out
