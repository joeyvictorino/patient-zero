import json

import pytest
import yaml

from patient_zero.demo.leaky_clinic import target_for
from patient_zero import assess, profile, report
from patient_zero.auditlog import AuditLog
from patient_zero.cli import main
from patient_zero.probes import ProbeRefused, load_target, write_evidence
from patient_zero.probes import agent, isolation, offline, tls
from patient_zero.probes.common import request


def write_target(tmp_path, server, **overrides):
    target = target_for(server)
    target.update(overrides)
    path = tmp_path / "target.yaml"
    path.write_text(yaml.safe_dump(target))
    return str(path)


@pytest.mark.parametrize("missing", ["authorized", "synthetic_data_only", "authorization_ref"])
def test_probes_refuse_without_authorization(tmp_path, fixed_server, missing):
    target = target_for(fixed_server)
    target.pop(missing)
    path = tmp_path / "target.yaml"
    path.write_text(yaml.safe_dump(target))
    with pytest.raises(ProbeRefused):
        load_target(str(path))


def test_requests_stay_on_the_declared_target(fixed_server):
    target = target_for(fixed_server)
    with pytest.raises(ProbeRefused):
        request(target, "GET", "https://elsewhere.example/")
    with pytest.raises(ProbeRefused):
        request(target, "GET", "//elsewhere.example/")


def test_env_tokens(tmp_path, fixed_server, monkeypatch):
    monkeypatch.setenv("PZ_TOKEN_A", "tok-a")
    monkeypatch.setenv("PZ_TOKEN_B", "tok-b")
    path = write_target(tmp_path, fixed_server, tenants={"a": {"token": "env:PZ_TOKEN_A"}, "b": {"token": "env:PZ_TOKEN_B"}})
    assert isolation.run(load_target(path)).clean


def test_isolation_finds_cross_tenant_read(vulnerable_server):
    result = isolation.run(target_for(vulnerable_server))
    assert not result.clean
    assert {f.control for f in result.findings} == {"GATE-3"}
    assert len(result.findings) == 2  # other tenant and anonymous
    assert all(f.severity == "critical" for f in result.findings)


def test_isolation_clean_on_fixed_target(fixed_server):
    result = isolation.run(target_for(fixed_server))
    assert result.clean and result.checks == 3 and not result.inconclusive


def test_isolation_without_canary_uses_status(vulnerable_server):
    target = target_for(vulnerable_server)
    del target["isolation"]["canary"]
    result = isolation.run(target)
    assert [f.severity for f in result.findings] == ["high", "high"]


def test_isolation_reports_untestable_route(fixed_server):
    target = target_for(fixed_server)
    target["isolation"]["resources"] = [{"path": "/api/workspaces/missing/clients"}]
    result = isolation.run(target)
    assert result.clean and len(result.inconclusive) == 1


def test_agent_finds_leak_and_injection(vulnerable_server):
    result = agent.run(target_for(vulnerable_server))
    assert {f.control for f in result.findings} == {"MEM-1", "AGENT-4"}


def test_agent_clean_on_fixed_target(fixed_server):
    result = agent.run(target_for(fixed_server))
    assert result.clean and result.checks == 6 and not result.inconclusive


def test_egress_probe(tmp_path, fixed_server):
    (tmp_path / "register.yaml").write_text(yaml.safe_dump({"endpoints": [
        {"host": "api.model.example", "baa": True, "training_on_phi": "prohibited", "retention": "0 days"},
        {"host": "old.vendor.example", "baa": False},
    ]}))
    (tmp_path / "observed.txt").write_text("# export\napi.model.example\nanalytics.tracker.example\n")
    path = write_target(tmp_path, fixed_server, egress={"register": "register.yaml", "observed": "observed.txt"})
    result = offline.run_egress(load_target(path))
    assert sorted(f.control for f in result.findings) == ["TRUST-1", "TRUST-2"]


def test_log_probe(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    log.append(user="u", workspace="w", action="x", obj="o")
    assert offline.run_log(log.path, log.head()).clean
    assert not offline.run_log(log.path, "f" * 64).clean


def test_tls_probe_on_plain_http():
    remote = {"base_url": "http://app.example.com"}
    assert [f.control for f in tls.run(remote).findings] == ["BASE-2"]
    local = {"base_url": "http://127.0.0.1:9"}
    assert tls.run(local).clean and tls.run(local).inconclusive


def test_evidence_file_is_hashed(tmp_path, fixed_server):
    result = isolation.run(target_for(fixed_server))
    path = write_evidence(result, str(tmp_path / "evidence"))
    stored = json.load(open(path))
    assert len(stored["sha256"]) == 64 and stored["result"]["probe"] == "isolation"


def test_probe_results_never_pass_a_control(vulnerable_server, fixed_server):
    prof = profile.load()
    data = assess.new("demo", "L2", prof)

    assess.apply_probe(data, isolation.run(target_for(vulnerable_server)), "e1.json")
    assert data["controls"]["GATE-3"]["status"] == "fail"
    assert data["controls"]["TEST-1"]["status"] == "partial"

    assess.apply_probe(data, isolation.run(target_for(fixed_server)), "e2.json")
    assert data["controls"]["GATE-3"]["status"] == "partial"
    assert data["controls"]["GATE-3"]["evidence"] == ["e1.json", "e2.json"]

    assess.set_status(data, "GATE-3", "pass", note="reviewed route inventory", assessor="jv")
    assess.apply_probe(data, isolation.run(target_for(fixed_server)), "e3.json")
    assert data["controls"]["GATE-3"]["status"] == "pass"  # clean run leaves a human pass alone
    assess.apply_probe(data, isolation.run(target_for(vulnerable_server)), "e4.json")
    assert data["controls"]["GATE-3"]["status"] == "fail"  # a finding overrides it


def test_set_status_rules():
    data = assess.new("demo", "L0", profile.load())
    with pytest.raises(ValueError):
        assess.set_status(data, "GATE-1", "pass")  # no evidence
    with pytest.raises(ValueError):
        assess.set_status(data, "GATE-1", "not_applicable")  # no reason
    with pytest.raises(KeyError):
        assess.set_status(data, "AGENT-1", "pass", evidence=["x"])  # not required at L0
    assess.set_status(data, "GATE-1", "pass", evidence=["config.png"])
    assert data["controls"]["GATE-1"]["status"] == "pass"


def test_summary_and_report():
    prof = profile.load()
    data = assess.new("demo", "L0", prof)
    assert not assess.summarize(data, prof)["conformant"]
    for cid in data["controls"]:
        assess.set_status(data, cid, "pass", evidence=["e.json"])
    summary = assess.summarize(data, prof)
    assert summary["conformant"] and summary["counts"]["pass"] == 5
    text = report.render(data, prof)
    assert "conforms to L0" in text and "not a HIPAA certification" in text and "GATE-4" in text


def test_cli_end_to_end(tmp_path, vulnerable_server, fixed_server, capsys):
    a = str(tmp_path / "assessment.yaml")
    ev = str(tmp_path / "evidence")
    assert main(["init", "--product", "demo", "--level", "L2", "-o", a]) == 0

    bad = write_target(tmp_path, vulnerable_server)
    assert main(["probe", "isolation", "--config", bad, "-a", a, "--evidence-dir", ev]) == 1
    assert main(["probe", "agent", "--config", bad, "-a", a, "--evidence-dir", ev]) == 1
    assert main(["report", a, "--strict"]) == 1

    good = write_target(tmp_path, fixed_server)
    assert main(["probe", "isolation", "--config", good, "-a", a, "--evidence-dir", ev]) == 0
    assert main(["probe", "agent", "--config", good, "-a", a, "--evidence-dir", ev]) == 0
    assert main(["set", "MEM-1", "pass", "--note", "canary run reviewed", "-a", a]) == 0

    out_md = str(tmp_path / "report.md")
    assert main(["report", a, "-o", out_md]) == 0
    text = open(out_md).read()
    assert "| MEM-1 | Pass |" in text and "| AGENT-4 | Partial |" in text

    capsys.readouterr()
    assert main(["report", a, "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["counts"]["pass"] == 1 and not summary["conformant"]


def test_cli_refuses_unauthorized_target(tmp_path, fixed_server, capsys):
    target = target_for(fixed_server)
    target["authorized"] = False
    path = tmp_path / "t.yaml"
    path.write_text(yaml.safe_dump(target))
    assert main(["probe", "isolation", "--config", str(path)]) == 2
    assert "refused" in capsys.readouterr().err
