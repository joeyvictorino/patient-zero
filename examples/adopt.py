"""Minimal wiring of the reference safeguards into an application."""
from patient_zero.auditlog import AuditLog
from patient_zero.egress import EgressGuard, load_register
from patient_zero.gate import BAARecord, PHIAccessDenied, PHIGate
from patient_zero.phi import likely_phi
from patient_zero.policy import ActionGate, Policy, Proposal

audit = AuditLog("audit.jsonl")

BAAS = {"ws_clinic": BAARecord("ws_clinic", executed=True, approved_by="owner@clinic.example")}
gate = PHIGate(lookup=BAAS.get, audit=audit)
egress = EgressGuard(load_register("examples/register.example.yaml"))


@gate.guard
def save_note(workspace_id: str, user: str, note: str) -> None:
    audit.append(user=user, workspace=workspace_id, action="note.write", obj="note:1")


def save_note_any_workspace(workspace_id: str, user: str, note: str) -> str:
    try:
        save_note(workspace_id, user, note)
        return "saved in the PHI enclave"
    except PHIAccessDenied:
        if likely_phi(note):  # GATE-5: keep PHI out of non-PHI workspaces
            return "blocked: this workspace is not enabled for PHI"
        return "saved in the standard workspace"


POLICY = Policy(
    version="2026.1",
    allowed_capabilities=frozenset({"record.read", "email.send"}),
    allowed_outputs=frozenset({"appointment_count"}),
    write_capabilities=frozenset({"email.send"}),
    confirm_actions=frozenset({"email.send"}),
)
agent_gate = ActionGate(POLICY, workspace="ws_clinic", audit=audit,
                        user_capabilities=lambda user: {"record.read"})


def agent_summary(nonce: str) -> dict:
    from datetime import datetime, timedelta, timezone

    proposal = Proposal(agent="assistant-1", user="dr.a", workspace="ws_clinic", action="record.summarize",
                        capabilities=frozenset({"record.read"}), outputs=frozenset({"appointment_count"}), nonce=nonce,
                        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), policy_version="2026.1")
    decision = agent_gate.evaluate(proposal)
    if not decision.allowed:
        return {"denied": decision.reason}
    raw = {"appointment_count": 3, "note_text": "full clinical note"}   # what the agent produced
    return agent_gate.release(proposal, raw)                            # what is allowed to leave


if __name__ == "__main__":
    print(save_note_any_workspace("ws_clinic", "dr.a", "Patient DOB: 01/02/1980, follow up in 2 weeks"))
    print(save_note_any_workspace("ws_studio", "sam", "Patient DOB: 01/02/1980, follow up in 2 weeks"))
    print(save_note_any_workspace("ws_studio", "sam", "Send the Q3 sponsorship deck"))
    egress.require("https://api.model-vendor.example/v1/messages")
    print("egress to the registered model vendor allowed")
    print("agent result released:", agent_summary("n-1"))
    print("same proposal replayed:", agent_summary("n-1"))
