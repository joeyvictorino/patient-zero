"""Pilots, sandboxes, cohorts and briefs: the pieces for people who convene vendors and buyers."""
import base64
import json
import os

import pytest
import yaml

from patient_zero import assess, brief, buyer, check, fleet, phi, pilot, profile, sandbox, seal, synth
from patient_zero.cli import main
from patient_zero.demo.leaky_clinic import target_for
from patient_zero.probes import ProbeRefused
from patient_zero.probes.common import ProbeResult

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROF = profile.load()


# --- synthetic records --------------------------------------------------------

def test_synthetic_records_are_repeatable_marked_and_cannot_be_real():
    data = synth.generate(patients=30, seed=7, tenants=3)
    assert data == synth.generate(patients=30, seed=7, tenants=3) and data != synth.generate(patients=30, seed=8, tenants=3)
    people = [p for t in data["tenants"] for p in t["patients"]]
    assert len(people) == 30 and len({p["mrn"] for p in people}) == 30
    for p in people:
        assert synth.looks_synthetic(p)
        assert 900 <= int(p["ssn"][:3]) <= 999             # a range that is never issued
        assert p["phone"].startswith("702-555-01")         # reserved for fiction
    markers = [t["canary"] for t in data["tenants"]]
    assert len(set(markers)) == 3
    for tenant in data["tenants"]:
        text = json.dumps(tenant["patients"])
        assert tenant["canary"] in text and not any(m in text for m in markers if m != tenant["canary"])
    assert not synth.looks_synthetic({**people[0], "ssn": "123-45-6789"})
    kinds = {f.kind for f in phi.scan(synth.to_csv(data), strict=True)}
    assert {"phone", "email"} <= kinds                    # shaped like a chart, though every identifier is in a never-issued range
    assert synth.to_csv(data).count("\n") == 31
    with pytest.raises(ValueError):
        synth.generate(patients=0)


# --- the pilot kit ------------------------------------------------------------

def start_pilot(tmp_path, server, **extra):
    folder = str(tmp_path / "pilot")
    pilot.init(folder, "Sample Scribe", base_url=f"http://127.0.0.1:{server.server_address[1]}", seed=3)
    return folder


def authorize(folder, server):
    target = target_for(server)
    target["authorization_ref"] = "rules-of-engagement.md, signed 2026-11-22 by the owner"
    with open(os.path.join(folder, "target.yaml"), "w") as fh:
        yaml.safe_dump(target, fh)


def test_pilot_init_writes_everything_and_starts_unauthorized(tmp_path, fixed_server):
    folder = start_pilot(tmp_path, fixed_server)
    for name in ("rules-of-engagement.md", "target.yaml", "register.yaml", "synthetic-patients.json", "synthetic-patients.csv",
                 "PILOT.md", "assessment.yaml"):
        assert os.path.isfile(os.path.join(folder, name)), name
    target = yaml.safe_load(open(os.path.join(folder, "target.yaml")))
    assert target["authorized"] is False and target["synthetic_data_only"] is True and target["authorized_hosts"] == ["127.0.0.1"]
    marker = json.load(open(os.path.join(folder, "synthetic-patients.json")))["tenants"][0]["canary"]
    assert target["isolation"]["canary"] == marker
    rules = open(os.path.join(folder, "rules-of-engagement.md")).read()
    assert "Synthetic data only" in rules and "Signatures" in rules and "127.0.0.1" in rules
    with pytest.raises(ProbeRefused):
        pilot.run(folder)                                   # nobody has signed
    with pytest.raises(FileExistsError):
        pilot.init(folder, "Sample Scribe")                 # never overwrites


def test_pilot_run_reports_a_clean_run_without_calling_it_a_pass(tmp_path, fixed_server):
    folder = start_pilot(tmp_path, fixed_server)
    authorize(folder, fixed_server)
    outcome = pilot.run(folder)
    assert {r["probe"] for r in outcome["ran"]} >= {"isolation", "agent"} and not outcome["failed"]
    report = open(outcome["report"]).read()
    assert "A clean run is not a pass" in report and "signed 2026-11-22" in report and "What to test next" in report
    data = assess.load(os.path.join(folder, "assessment.yaml"))
    assert data["controls"]["GATE-3"]["status"] == "partial"        # tested clean, not confirmed


def test_pilot_run_finds_the_leak_and_cli_exits_1(tmp_path, vulnerable_server, capsys):
    folder = start_pilot(tmp_path, vulnerable_server)
    authorize(folder, vulnerable_server)
    project = tmp_path / "src"
    project.mkdir()
    (project / "app.ts").write_text("new OpenAI({ dangerouslyAllowBrowser: true })\n")
    assert main(["pilot", "run", folder, "--path", str(project)]) == 1
    report = open(os.path.join(folder, "pilot-report.md")).read()
    assert "returned tenant A's data to another tenant" in report and "The AI model is called straight from the browser" in report
    assert assess.load(os.path.join(folder, "assessment.yaml"))["controls"]["GATE-3"]["status"] == "fail"


# --- sandbox criteria ---------------------------------------------------------

def by_id(rows):
    return {r["id"]: r["status"] for r in rows}


def test_sandbox_criteria_move_from_unmet_to_met(tmp_path, fixed_server):
    folder = start_pilot(tmp_path, fixed_server)
    first = sandbox.evaluate(folder)
    assert not first["entry_met"] and by_id(first["entry"]) == {
        "permission": "not met", "synthetic": "met", "assessment": "met", "register": "not met", "no-critical-code": "not checked"}

    authorize(folder, fixed_server)
    good = {"host": "api.model.example", "baa": True, "training_on_phi": "prohibited", "retention": "0 days"}
    yaml.safe_dump({"endpoints": [good]}, open(os.path.join(folder, "register.yaml"), "w"))
    project = tmp_path / "src"
    project.mkdir()
    (project / "app.py").write_text("print('ok')\n")
    entered = sandbox.evaluate(folder, str(project))
    assert entered["entry_met"] and not entered["exit_met"]
    assert by_id(entered["exit"])["isolation-tested"] == "not met" and by_id(entered["exit"])["sealed"] == "not met"

    pilot.run(folder)
    seal.keygen(os.path.join(folder, "vendor.key"))
    seal.keygen(os.path.join(folder, "assessor.key"))
    seal.seal(os.path.join(folder, "assessment.yaml"), os.path.join(folder, "vendor.key"), os.path.join(folder, "seal.json"))
    sealed = sandbox.evaluate(folder, str(project))
    assert by_id(sealed["exit"]) == {"isolation-tested": "met", "nothing-failing": "met", "agreements": "met", "no-serious-code": "met",
                                     "sealed": "met", "independent": "not met"}
    seal.cosign(os.path.join(folder, "seal.json"), os.path.join(folder, "assessor.key"), "Example Assessors", "independent-assessor")
    assert sandbox.evaluate(folder, str(project))["exit_met"]
    text = sandbox.render(sandbox.evaluate(folder, str(project)))
    assert "TO LEAVE: 6 of 6 met" in text and "operator decides" in text and "not a certification" in text


def test_sandbox_criteria_file_matches_the_code():
    ids = [c["id"] for stage in sandbox.criteria().values() for c in stage]
    assert len(ids) == len(set(ids)) == 11 and set(sandbox.criteria()) == {"entry", "exit"}
    assert main(["sandbox", os.path.join(ROOT, "examples")]) == 1     # a folder that is not a pilot meets nothing, and does not crash


# --- many reports at once -----------------------------------------------------

def make_bundle(tmp_path, folder, product, fail=None, confirm=(), cosign=False):
    work = tmp_path / product.replace(" ", "-")
    os.makedirs(work / "evidence")
    (work / "evidence" / "e.json").write_text("{}")
    data = assess.new(product, "L1", PROF)
    for cid in confirm:
        assess.set_status(data, cid, "pass", evidence=["evidence/e.json"])
    if fail:
        result = ProbeResult("isolation", [fail], "t")
        result.checks_for = {fail: 2}
        result.add(fail, "critical", "leak")
        assess.apply_probe(data, result, "evidence/e.json")
    assess.save(data, str(work / "assessment.yaml"))
    seal.keygen(str(work / "k"))
    seal.seal(str(work / "assessment.yaml"), str(work / "k"), str(work / "seal.json"), signer_name=product, domain="vendor.example")
    if cosign:
        seal.keygen(str(work / "a"))
        seal.cosign(str(work / "seal.json"), str(work / "a"), "Example Assessors", "independent-assessor")
    out = os.path.join(folder, product.replace(" ", "-") + ".json")
    seal.bundle(str(work / "seal.json"), out)
    return out


def test_vendor_view_flags_what_a_clinic_should_raise_and_cohort_view_ranks_nobody(tmp_path, capsys):
    folder = str(tmp_path / "bundles")
    os.makedirs(folder)
    make_bundle(tmp_path, folder, "Alpha Notes", fail="GATE-3", confirm=("BASE-1",))
    make_bundle(tmp_path, folder, "Beta Scribe", fail="GATE-3", confirm=("BASE-1", "BASE-2"), cosign=True)
    tampered = make_bundle(tmp_path, folder, "Gamma Chart")
    packed = json.load(open(tampered))
    packed["files"]["assessment.yaml"] = base64.b64encode(b"product: Gamma Chart\nlevel: L1\ncontrols: {}\n").decode()
    json.dump(packed, open(tampered, "w"))
    (tmp_path / "bundles" / "notes.json").write_text('{"not": "a bundle"}')

    rows = fleet.read(folder)
    assert [r["product"] for r in rows] == ["Alpha Notes", "Beta Scribe", "Gamma Chart"]
    alpha, beta, gamma = rows
    assert alpha["verified"] and any("failing" in f for f in alpha["flags"]) and any("nobody independent" in f for f in alpha["flags"])
    assert beta["independent_cosigners"] == 1 and not any("nobody independent" in f for f in beta["flags"])
    assert not gamma["verified"] and gamma["flags"][0].startswith("DOES NOT VERIFY")

    stats = fleet.cohort(rows)
    assert (stats["reports"], stats["verified"], stats["not_verified"], stats["with_failing"]) == (3, 2, 1, 2)
    assert stats["most_often_failing"][0] == {"id": "GATE-3", "assessed_by": 2, "fail": 2, "pass": 0, "partial": 0, "not_assessed": 0}
    assert "GATE-1" in stats["never_confirmed"] and "BASE-1" not in stats["never_confirmed"]

    named, anonymous = fleet.render(rows), fleet.render(rows, anonymize=True)
    assert "Alpha Notes" in named and "walled off from every other customer" in named and "GATE-3 | " in named
    assert "Product A" in anonymous and not any(name in anonymous for name in ("Alpha", "Beta", "Gamma"))
    assert "ranks nobody" in anonymous and "compliant or certified" in anonymous
    assert main(["vendors", folder, "--anonymize"]) == 1          # one bundle does not verify
    assert "did not verify" in capsys.readouterr().out
    empty = tmp_path / "none"
    empty.mkdir()
    assert main(["vendors", str(empty)]) == 2


# --- briefs and the review form -----------------------------------------------

def test_generated_briefs_and_review_form_are_up_to_date():
    docs = os.path.join(ROOT, "docs")
    assert open(os.path.join(docs, "LEGISLATOR-BRIEF.md")).read() == brief.render("legislator", "nevada")
    assert open(os.path.join(docs, "PITCH-SCORECARD.md")).read() == brief.render("judge")
    assert open(os.path.join(docs, "NEVADA-REVIEW.md")).read() == buyer.overlay_review("nevada")


def test_briefs_are_tied_to_real_controls_and_take_no_position():
    ids = {c.id for c in PROF.controls}
    overlay = {i["id"] for i in buyer.load_overlay("nevada")["items"]}
    doc = brief.load()
    assert len(doc["legislator"]["questions"]) == 10 and len(doc["judge"]["questions"]) == 8
    for audience in brief.AUDIENCES:
        for q in doc[audience]["questions"]:
            assert q["ask"].endswith("?") and set(q["controls"]) <= ids and set(q.get("overlay", [])) <= overlay
    text = brief.render("legislator", "nevada")
    assert "takes no position on any bill" in text and "Not legal advice" in text
    assert "not a finding that no rule exists" in text          # silence in the overlay is not a claim about the law
    for word in ("should pass", "must legislate", "we recommend", "support the bill"):
        assert word not in text.lower()
    assert "Nevada today" not in brief.render("legislator")     # no overlay, no state claims
    form = buyer.overlay_review("nevada")
    assert form.count("- [ ] The citation points to the right provision.") == 6 and "no attorney-client relationship" in form


def test_lab_answer_key_matches_what_the_check_really_says():
    result = check.run(os.path.join(ROOT, "examples", "vibe-clinic"))
    groups = check.grouped(result)
    notes = open(os.path.join(ROOT, "docs", "workshop", "INSTRUCTOR.md")).read()
    assert len(groups) == 12 and "Twelve kinds" in notes
    assert [g["issue"].rule for g in groups[:3]] == ["browser-model-call", "browser-model-key", "env-file-committed"]
    assert not any("api.py" in place and "notes" in place for g in groups for place in g["places"] if g["issue"].rule == "isolation")
    lab = open(os.path.join(ROOT, "docs", "workshop", "LAB.md")).read()
    assert "pz check examples/vibe-clinic" in lab and "pz demo --brief" in lab
