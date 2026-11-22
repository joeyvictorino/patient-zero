"""What a buyer relies on: bundles, co-signatures, identity, the badge, the spec's vectors and the browser verifier."""
import base64
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from patient_zero import assess, badge, bayes, conformance, profile, seal
from patient_zero.cli import main
from patient_zero.probes.common import ProbeResult

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROF = profile.load()


@pytest.fixture
def sealed(tmp_path):
    os.makedirs(tmp_path / "evidence")
    (tmp_path / "evidence" / "mfa.json").write_text('{"mfa": "on"}')
    data = assess.new("Acme Scribe", "L1", PROF)
    data["build"] = "2026.11.1"
    assess.set_status(data, "BASE-1", "pass", evidence=["evidence/mfa.json"], independent=True)
    assess.set_status(data, "GATE-1", "pass", evidence=["evidence/mfa.json"])
    failing = ProbeResult("isolation", ["GATE-3"], "t")
    failing.checks_for = {"GATE-3": 2}
    failing.add("GATE-3", "critical", "cross-tenant read")
    (tmp_path / "evidence" / "iso.json").write_text("{}")
    assess.apply_probe(data, failing, "evidence/iso.json")
    a = str(tmp_path / "assessment.yaml")
    assess.save(data, a)
    seal.keygen(str(tmp_path / "vendor.key"))
    seal.keygen(str(tmp_path / "assessor.key"))
    out = str(tmp_path / "seal.json")
    seal.seal(a, str(tmp_path / "vendor.key"), out, signer_name="Acme Health", domain="Acme.Example")
    return tmp_path, out


def test_the_signed_summary_counts_what_was_claimed_and_cannot_be_improved(sealed):
    tmp, out = sealed
    doc = json.load(open(out))
    s = doc["head"]["summary"]
    assert (s["controls"], s["confirmed"], s["failed"], s["confirmed_by_independent"], s["confirmed_by_self_only"]) == (43, 2, 1, 1, 1)
    assert s["with_probe_evidence"] == 1 and s["build"] == "2026.11.1" and doc["head"]["signer"]["domain"] == "acme.example"
    assert all(isinstance(v, (int, str)) or v is None for v in s.values())      # no floats inside signed data
    doc["head"]["summary"]["failed"] = 0
    json.dump(doc, open(out, "w"))
    assert "signature does not verify" in seal.verify_seal(out)
    with pytest.raises(ValueError):
        seal.seal(str(tmp / "assessment.yaml"), str(tmp / "vendor.key"), str(tmp / "s2.json"), domain="https://acme.example/x")


def test_cosignature_binds_to_one_seal_and_needs_a_second_key(sealed):
    tmp, out = sealed
    with pytest.raises(ValueError, match="different key"):
        seal.cosign(out, str(tmp / "vendor.key"), "Acme", "independent-assessor")
    with pytest.raises(ValueError, match="role"):
        seal.cosign(out, str(tmp / "assessor.key"), "X", "auditor-general")
    seal.cosign(out, str(tmp / "assessor.key"), "Example Assessors", "independent-assessor", "Reviewed MFA.", "assessors.example")
    assert seal.verify_seal(out) == []
    info = seal.describe(json.load(open(out)))
    assert info["cosigners"][0]["role"] == "independent-assessor" and info["age_days"] == 0
    doc = json.load(open(out))
    doc["cosignatures"][0]["body"]["statement"] = "Reviewed everything."
    json.dump(doc, open(out, "w"))
    assert any("co-signature by Example Assessors does not verify" in e for e in seal.verify_seal(out))
    # resealing makes a new seal; the old co-signature must not carry over to it
    again = seal.seal(str(tmp / "assessment.yaml"), str(tmp / "vendor.key"), out)
    assert "cosignatures" not in again
    (tmp / "evidence" / "mfa.json").write_text("changed")
    with pytest.raises(ValueError, match="does not verify|refusing"):
        seal.bundle(out, str(tmp / "b.json"))


def test_bundle_round_trip_and_tamper(sealed):
    tmp, out = sealed
    path = str(tmp / "bundle.json")
    seal.bundle(out, path)
    errors, document = seal.verify_bundle(path)
    assert errors == [] and document["head"]["product"] == "Acme Scribe"
    packed = json.load(open(path))
    packed["files"]["evidence/mfa.json"] = base64.b64encode(b'{"mfa": "off"}').decode()
    json.dump(packed, open(path, "w"))
    assert seal.verify_bundle(path)[0] == ["changed since sealing: evidence/mfa.json"]
    del packed["files"]["evidence/mfa.json"]
    json.dump(packed, open(path, "w"))
    assert seal.verify_bundle(path)[0] == ["missing: evidence/mfa.json"]
    json.dump({"hello": 1}, open(path, "w"))
    assert seal.verify_bundle(path)[0] == ["not a patient-zero bundle"]


def test_identity_ties_a_key_to_a_domain_without_touching_the_network(sealed):
    tmp, out = sealed
    doc = json.load(open(out))
    key = doc["head"]["signer"]["public_key"]
    identity = seal.identity_document("acme.example", [key])
    assert seal.check_domains(doc, fetch=lambda domain: identity) == []
    assert seal.check_domains(doc, fetch=lambda d: seal.identity_document("acme.example", ["00" * 32])) == ["acme.example does not list this key"]
    retired = seal.identity_document("acme.example", [], retired=[key])
    assert seal.check_domains(doc, fetch=lambda d: retired) == ["acme.example lists this key as retired"]
    assert "not acme.example" in seal.check_domains(doc, fetch=lambda d: seal.identity_document("evil.example", [key]))[0]

    def down(domain):
        raise OSError("no route")

    assert "could not read https://acme.example/.well-known/patient-zero.json" in seal.check_domains(doc, fetch=down)[0]
    plain = seal.seal(str(tmp / "assessment.yaml"), str(tmp / "vendor.key"), str(tmp / "plain.json"))
    assert "names no domain" in seal.check_domains(plain, fetch=lambda d: identity)[0]


def test_verify_never_opens_a_connection_unless_asked(sealed, monkeypatch, capsys):
    tmp, out = sealed
    called = []
    monkeypatch.setattr(seal, "fetch_identity", lambda domain, timeout=10.0: called.append(domain) or {})
    assert main(["verify", out]) == 0 and called == []
    printed = capsys.readouterr().out
    assert "2 of 43 safeguards confirmed by a person (1 by someone independent)" in printed and "1 failing" in printed
    assert "does not show the claims in them are true" in printed


def test_badge_states_counts_and_never_a_verdict(sealed, capsys):
    tmp, out = sealed
    doc = json.load(open(out))
    text = badge.message(doc)
    assert text.startswith("L1 · 2/43 confirmed · 1 failing · sealed ")
    svg = badge.svg(doc)
    assert badge.WARNING in svg and "not a certification" in svg
    for word in ("compliant ", "certified", "passed", "approved"):
        assert word not in svg.replace("does not mean HIPAA compliant", "").lower()
    assert "green" not in svg and "#4c1" not in svg and "#0a0" not in svg
    target = str(tmp / "badge.svg")
    assert main(["badge", out, "--report-url", "https://acme.example/trust/", "-o", target]) == 0
    printed = capsys.readouterr().out
    assert "](https://acme.example/trust/)" in printed and "not a certification" in printed
    doc["head"]["level"] = "L2"
    json.dump(doc, open(out, "w"))
    assert main(["badge", out, "--report-url", "https://x.example", "-o", target]) == 1      # no badge from a seal that does not verify


def test_old_seals_are_called_old():
    now = datetime(2026, 11, 22, tzinfo=timezone.utc)
    head = {"sealed_at": (now - timedelta(days=430)).isoformat()}
    assert seal.describe({"head": head}, now)["age_days"] == 430 and seal.age_phrase(430) == "about 14 months ago"
    assert seal.age_phrase(0) == "today" and seal.age_phrase(None) == "at an unknown time"


def test_cli_flow_seal_cosign_bundle_verify(sealed, capsys):
    tmp, out = sealed
    assert main(["cosign", out, "--key", str(tmp / "assessor.key"), "--name", "EA", "--role", "independent-assessor"]) == 0
    bundle = str(tmp / "b.json")
    assert main(["bundle", out, "-o", bundle]) == 0 and main(["verify", bundle]) == 0
    assert "co-signed by EA as independent-assessor" in capsys.readouterr().out
    assert main(["identity", "--domain", "acme.example", "--key", str(tmp / "vendor.key"), "-o", str(tmp / "id.json")]) == 0
    assert json.load(open(tmp / "id.json"))["keys"][0]["status"] == "active"


# --- the standard -------------------------------------------------------------

def test_this_implementation_passes_every_vector():
    assert conformance.run() == []
    assert main(["conformance"]) == 0


def test_vectors_are_what_the_generator_writes(tmp_path):
    """A vector may change only on purpose: regenerate and compare."""
    before = {name: open(os.path.join(ROOT, "patient_zero", "data", "vectors", name)).read()
              for name in os.listdir(os.path.join(ROOT, "patient_zero", "data", "vectors"))}
    assert set(before) == {f"{kind}.json" for kind in conformance.KINDS}
    samples = open(os.path.join(ROOT, "docs", "verify", "samples.js")).read()
    env = {**os.environ, "PYTHONPATH": ROOT + os.pathsep + os.environ.get("PYTHONPATH", "")}
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_vectors.py")], check=True, capture_output=True, env=env)
    assert open(os.path.join(ROOT, "docs", "verify", "samples.js")).read() == samples
    after = {name: open(os.path.join(ROOT, "patient_zero", "data", "vectors", name)).read() for name in before}
    assert after == before, "run tools/make_vectors.py and review the diff; a changed vector is a change to the standard"


def test_a_broken_implementation_fails_the_vectors(monkeypatch, tmp_path):
    monkeypatch.setattr(seal, "_canonical", lambda value: json.dumps(value).encode())      # unsorted, spaced
    failures = conformance.run()
    assert any(f.startswith("canonical-json /") for f in failures) and any(f.startswith("seal /") for f in failures)
    assert conformance.run(str(tmp_path)) == ["no vector files found"]


def test_spec_names_every_vector_kind_and_schema():
    spec = open(os.path.join(ROOT, "spec", "SPEC.md")).read()
    for kind in conformance.KINDS:
        assert f"`{kind}`" in spec, kind
    for schema in (seal.SCHEMA, seal.COSIGN_SCHEMA, seal.BUNDLE_SCHEMA, seal.IDENTITY_SCHEMA):
        assert schema in spec


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_browser_verifier_passes_the_same_vectors():
    done = subprocess.run(["node", os.path.join(ROOT, "tools", "run_vectors.js")], capture_output=True, text=True)
    assert done.returncode == 0 and "CONFORMS" in done.stdout, done.stdout + done.stderr


def test_verify_page_loads_nothing_from_elsewhere():
    page = open(os.path.join(ROOT, "docs", "verify", "index.html")).read()
    assert "default-src 'none'" in page and "script-src 'self'" in page
    assert 'src="http' not in page and "@import" not in page
    assert "not a certification" in page and "Nothing you drop here leaves your computer" in page
    script = open(os.path.join(ROOT, "docs", "verify", "page.js")).read()
    assert script.count("fetch(") == 1      # only the identity check the reader clicks


# --- pooled calibration -------------------------------------------------------

def test_calibration_export_drops_names_and_pools(tmp_path, capsys):
    data = assess.new("Secret Product", "L1", PROF)
    for who, p, clean in (("Pat Example", 0.9, False), ("Lee Example", 0.4, False), ("Pat Example", 0.7, True)):
        assess.predict(data, "isolation", p, who, 0.65)
        result = ProbeResult("isolation", ["GATE-3"], "t")
        result.checks_for = {"GATE-3": 2}
        if not clean:
            result.add("GATE-3", "high", "x")
        assess.apply_probe(data, result, "e.json")
    assess.predict(data, "agent", 0.5, "Pat Example", 0.6)                    # still open: not exported
    exported = bayes.export_calibration(data)
    text = json.dumps(exported)
    assert "Pat" not in text and "Lee" not in text and "Secret Product" not in text
    assert len(exported["records"]) == 3 and {r["forecaster"] for r in exported["records"]} == {"f1", "f2"}
    assert all(len(r["month"]) == 7 for r in exported["records"])
    a = str(tmp_path / "assessment.yaml")
    assess.save(data, a)
    pool = tmp_path / "pool"
    pool.mkdir()
    assert main(["calibration", a, "--export", str(pool / "one.json")]) == 0
    (pool / "junk.json").write_text('{"schema": "something-else"}')
    pooled = bayes.pooled_calibration([json.load(open(pool / n)) for n in sorted(os.listdir(pool))])
    assert pooled["files"] == 1 and pooled["settled"] == 3
    row = pooled["probes"][0]
    assert row["probe"] == "isolation" and row["clean_rate"] == pytest.approx(1 / 3)
    assert row["brier_model"] == pytest.approx((0.65 ** 2 * 2 + 0.35 ** 2) / 3)
    capsys.readouterr()
    assert main(["calibration", "--pool", str(pool)]) == 0
    assert "Fewer than 100 settled predictions" in capsys.readouterr().out


# --- signing backend ----------------------------------------------------------

def test_audited_and_pure_python_signers_agree():
    from patient_zero.custody import backend, generate_keypair, sign, verify

    pytest.importorskip("cryptography")
    assert backend() == "cryptography"
    for seed_text, message in ((b"a", b""), (b"b", b"patient-zero"), (b"c", bytes(range(256)) * 9)):
        seed, public = generate_keypair(seed_text)
        assert sign(message, seed) == sign(message, seed, pure=True)
        assert verify(message, sign(message, seed), public)
