"""The buyer's side: plain language, questionnaire, executive summary, Nevada overlay."""
import os

import pytest

from patient_zero import assess, buyer, nevada, profile
from patient_zero.cli import main
from patient_zero.probes.common import ProbeResult

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROF = profile.load()
JARGON = ("enclave", "allowlist", "hash", "tenant", "egress", "nonce", "idor", "embedding", "subprocessor")


def test_every_control_has_plain_language_and_no_jargon():
    plain = buyer.load_plain()
    assert set(plain) == {c.id for c in PROF.controls}
    for cid, entry in plain.items():
        assert set(entry) == {"plain", "ask", "proof"}, cid
        assert entry["ask"].rstrip().endswith("?"), cid
        text = " ".join(entry.values()).lower()
        for word in JARGON:
            assert word not in text, f"{cid} uses '{word}'"
        assert len(entry["plain"]) < 190, cid


def test_questionnaire_covers_the_level_and_the_overlay():
    text = buyer.questionnaire(PROF, "L1", "nevada")
    assert text.count("\n| ") - 2 * 8 == 35 + 5      # 7 family tables + Nevada, two header rows each
    assert "(GATE-1)" in text and "(AGENT-1)" not in text and "(NV-1)" in text
    assert "is not legal advice" in text
    assert "(AGENT-1)" in buyer.questionnaire(PROF, "L2")
    assert "(NV-1)" not in buyer.questionnaire(PROF, "L1")


def test_generated_buyer_documents_are_up_to_date():
    assert open(os.path.join(ROOT, "docs", "VENDOR-QUESTIONNAIRE.md")).read() == buyer.questionnaire(PROF, "L1", "nevada")
    assert open(os.path.join(ROOT, "docs", "NEVADA.md")).read() == buyer.overlay_markdown("nevada")


def test_nevada_overlay_is_well_formed():
    data = buyer.load_overlay("nevada")
    assert [i["id"] for i in data["items"]] == ["NV-1", "NV-2", "NV-3", "NV-4", "NV-5"]
    for item in data["items"]:
        assert item["law"] in data["laws"] and "shall" in item["statement"] and item["ask"].endswith("?")
    assert data["laws"]["AB406"]["effective"] == "2025-07-01"
    assert "not legal advice" in buyer.overlay_markdown("nevada")
    with pytest.raises(ValueError):
        buyer.load_overlay("atlantis")


def test_executive_summary_says_not_ready_when_something_failed():
    data = assess.new("Clinic Bot", "L1", PROF)
    failing = ProbeResult("isolation", ["GATE-3", "TEST-1"], "t")
    failing.checks_for = {"GATE-3": 2, "TEST-1": 2}
    failing.add("GATE-3", "critical", "returned tenant A's data to another tenant")
    assess.apply_probe(data, failing, "e.json")
    text = buyer.executive_summary(data, PROF)
    assert "Bottom line: not ready. 1 of 35 safeguards failed a test." in text
    assert "Our patients' data is walled off from every other customer's data.** This is not true today." in text
    assert "Tested by software, still needs a person" in text and "weak evidence, not proof" in text
    assert "is not a HIPAA certification" in text
    for word in ("GATE-3", "tenant isolation", "enclave"):
        assert word not in text.split("What the test found")[0]


def test_executive_summary_other_states():
    data = assess.new("Clinic Bot", "L0", PROF)
    assert "not yet shown to be ready" in buyer.executive_summary(data, PROF)
    for cid in data["controls"]:
        assess.set_status(data, cid, "pass", evidence=["e"])
    assert "every one of the 5 safeguards has been checked and confirmed" in buyer.executive_summary(data, PROF)


@pytest.mark.parametrize("sentence,kind", [
    ("Meet Sage, your AI therapist, available 24/7.", "ai_called_a_provider"),
    ("Our chatbot is your personal counselor.", "ai_called_a_provider"),
    ("A virtual psychiatrist in your pocket.", "ai_called_a_provider"),
    ("The assistant provides therapy between visits.", "ai_provides_care"),
    ("Get counseling from our AI in minutes.", "ai_provides_care"),
    ("Our AI diagnoses depression from a short conversation.", "ai_provides_care"),
    ("Talk to our chatbot for counseling whenever you need it.", "talk_to_ai_for_care"),
])
def test_care_claims_are_flagged(sentence, kind):
    assert [c.kind for c in nevada.findings(sentence)] == [kind]


@pytest.mark.parametrize("sentence", [
    "The assistant schedules appointments and drafts billing notes for your review.",
    "Our therapists use the tool to organize session notes.",
    "Book a visit with a licensed counselor through the app.",
    "The assistant is not a therapist and does not provide therapy.",
    "This chatbot cannot diagnose depression; please see a clinician.",
])
def test_administrative_copy_and_disclaimers_are_not_findings(sentence):
    assert nevada.findings(sentence) == []


def test_disclaimers_are_reported_separately():
    claims = nevada.scan_claims("The assistant is not a therapist and does not provide therapy.")
    assert [c.kind for c in claims] == ["disclaimer"]


def test_cli_buyer_commands(tmp_path, capsys):
    a = str(tmp_path / "a.yaml")
    assert main(["init", "--product", "Clinic Bot", "--level", "L1", "-o", a]) == 0
    capsys.readouterr()
    assert main(["report", a, "--executive"]) == 0
    assert "Bottom line" in capsys.readouterr().out
    assert main(["questionnaire", "--level", "L0"]) == 0
    assert "5 questions" in capsys.readouterr().out
    assert main(["overlay", "nevada"]) == 0
    assert "NV-4" in capsys.readouterr().out
    copy = tmp_path / "site.txt"
    copy.write_text("Meet Sage, your AI therapist.\nSage also schedules appointments.\n")
    assert main(["scan", str(copy), "--care-claims"]) == 1
    assert "ai_called_a_provider" in capsys.readouterr().out
    copy.write_text("Sage schedules appointments.\n")
    assert main(["scan", str(copy), "--care-claims"]) == 0


def test_leader_briefs_exist_in_both_languages_and_make_no_certification_claim():
    en = open(os.path.join(ROOT, "docs", "FOR-HEALTHCARE-LEADERS.md")).read()
    es = open(os.path.join(ROOT, "docs", "PARA-LIDERES-DE-SALUD.md")).read()
    assert "It is not a HIPAA certification" in en and "No es una certificación de HIPAA" in es
    assert "43 safeguards" in en and "43 salvaguardas" in es
    assert len(en.split()) < 450


def test_brief_demo_is_short_plain_and_true():
    from patient_zero.demo import run as demo_run

    lines = []
    assert demo_run.run_brief(out=lines.append) == 0
    text = "\n".join(lines)
    assert "NOT READY. 5 of 43 safeguards failed a test:" in text
    assert "All 5 now test clean, and 0 safeguards are failing." in text
    assert "0 of 43 are confirmed" in text
    assert "Seal checks out: yes." in text and "Caught: yes." in text
    assert len(text.splitlines()) <= 26 and max(len(line) for line in text.splitlines()) <= 80
    for word in ("GATE-3", "tenant", "Merkle", "Ed25519"):
        assert word not in text
