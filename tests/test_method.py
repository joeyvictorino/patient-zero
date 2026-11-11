"""Predictions before results, void runs, build-bound evidence, and offline replay."""
import json
from datetime import date

import pytest

from patient_zero import assess, bayes, profile, replay
from patient_zero.cli import main
from patient_zero.demo.leaky_clinic import target_for
from patient_zero.probes import agent, isolation, tls, write_evidence
from patient_zero.probes.common import ProbeResult

PROF = profile.load()
MODEL = bayes.load_model()


# --- replay -------------------------------------------------------------------

@pytest.mark.parametrize("probe", [isolation, agent])
def test_replay_reproduces_findings_and_clean_runs(probe, vulnerable_server, fixed_server, tmp_path):
    for server in (vulnerable_server, fixed_server):
        result = probe.run(target_for(server))
        path = write_evidence(result, str(tmp_path))
        assert result.exchanges and replay.replay(path) == (True, [])


def test_each_run_keeps_its_own_recording(vulnerable_server):
    target = target_for(vulnerable_server)
    first = isolation.run(target)
    count = len(first.exchanges)
    agent.run(target)
    assert len(first.exchanges) == count and all("workspaces" in x["path"] for x in first.exchanges)


def test_recording_holds_no_tokens(vulnerable_server, tmp_path):
    path = write_evidence(isolation.run(target_for(vulnerable_server)), str(tmp_path))
    text = open(path).read()
    assert "tok-a" not in text and "tok-b" not in text


def test_replay_catches_a_result_edited_by_hand(vulnerable_server, tmp_path):
    path = write_evidence(isolation.run(target_for(vulnerable_server)), str(tmp_path))
    doc = json.load(open(path))
    doc["result"]["findings"] = []
    doc["result"]["clean"] = True
    json.dump(doc, open(path, "w"))
    reproduced, differences = replay.replay(path)
    assert not reproduced and any("findings differ" in d for d in differences)


def test_replay_catches_a_doctored_recording(vulnerable_server, tmp_path):
    path = write_evidence(isolation.run(target_for(vulnerable_server)), str(tmp_path))
    doc = json.load(open(path))
    for exchange in doc["result"]["exchanges"][1:]:
        exchange["status"], exchange["body"] = 403, "{}"   # pretend the server refused
    json.dump(doc, open(path, "w"))
    reproduced, differences = replay.replay(path)
    assert not reproduced  # the file still claims findings the recording no longer supports


def test_replay_refuses_what_it_cannot_do(tmp_path):
    path = write_evidence(ProbeResult("egress", ["TRUST-2"], "t"), str(tmp_path))
    with pytest.raises(ValueError):
        replay.replay(path)
    path = write_evidence(ProbeResult("isolation", ["GATE-3"], "t"), str(tmp_path))
    with pytest.raises(ValueError):
        replay.replay(path)


def test_cli_replay(vulnerable_server, tmp_path, capsys):
    path = write_evidence(agent.run(target_for(vulnerable_server)), str(tmp_path))
    assert main(["replay", path]) == 0
    assert "REPRODUCED" in capsys.readouterr().out


# --- void runs ----------------------------------------------------------------

def test_a_run_that_tested_nothing_is_void_and_changes_nothing(fixed_server):
    target = target_for(fixed_server)
    target["isolation"]["resources"] = [{"path": "/api/workspaces/missing/clients"}]  # owner request fails
    result = isolation.run(target)
    assert result.clean and result.void
    data = assess.new("demo", "L1", PROF)
    assert assess.apply_probe(data, result, "e.json") == []
    assert data["controls"]["GATE-3"]["status"] == "not_assessed"
    assert data["controls"]["GATE-3"]["observations"] == []


def test_tls_on_localhost_is_void_not_clean():
    result = tls.run({"base_url": "http://127.0.0.1:9"})
    assert result.void


def test_agent_probe_asks_several_times(fixed_server):
    target = target_for(fixed_server)
    assert agent.run(target).checks_for["MEM-1"] == 12   # 4 prompts x 3 runs by default
    target["agent"]["runs"] = 1
    assert agent.run(target).checks_for["MEM-1"] == 4


# --- build-bound evidence -----------------------------------------------------

def test_evidence_from_another_build_counts_for_less(fixed_server):
    target = target_for(fixed_server)
    target["build"] = "1.0.0"
    data = assess.new("demo", "L1", PROF)
    assess.apply_probe(data, isolation.run(target), "e.json")
    assert data["build"] == "1.0.0"
    same = {r["id"]: r["p"] for r in bayes.beliefs(data, PROF, MODEL)}["GATE-3"]
    data["build"] = "1.1.0"   # a new release ships
    stale = {r["id"]: r["p"] for r in bayes.beliefs(data, PROF, MODEL)}["GATE-3"]
    assert 0.5 < stale < same


def test_cli_build(tmp_path, capsys):
    a = str(tmp_path / "a.yaml")
    assert main(["init", "--product", "x", "--level", "L0", "-o", a]) == 0
    assert main(["build", "2.0", "-a", a]) == 0
    assert assess.load(a)["build"] == "2.0"
    assert main(["set", "GATE-1", "pass", "--evidence", "e", "-a", a]) == 0
    assert assess.load(a)["controls"]["GATE-1"]["observations"][0]["build"] == "2.0"


# --- predictions --------------------------------------------------------------

def test_prediction_is_settled_by_the_next_real_run(vulnerable_server, fixed_server):
    data = assess.new("demo", "L2", PROF)
    model_p = bayes.predicted_clean(data, PROF, MODEL, "isolation")
    assert 0 < model_p < 1
    assess.predict(data, "isolation", 0.9, "pat", model_p)
    with pytest.raises(ValueError):
        assess.predict(data, "isolation", 0.1, "pat")       # no second guess while one is open
    assess.predict(data, "isolation", 0.2, "lee", model_p)   # someone else may disagree

    void_target = target_for(fixed_server)
    void_target["isolation"]["resources"] = [{"path": "/api/workspaces/missing/clients"}]
    assess.apply_probe(data, isolation.run(void_target), "v.json")
    assert all(q["outcome"] is None for q in data["predictions"])   # a void run settles nothing

    assess.apply_probe(data, isolation.run(target_for(vulnerable_server)), "e.json")
    assert [q["outcome"] for q in data["predictions"]] == ["finding", "finding"]
    assert data["predictions"][0]["settled"] == date.today().isoformat()

    rows = {r["forecaster"]: r for r in bayes.calibration(data)}
    assert rows["pat"]["brier"] == pytest.approx(0.81)
    assert rows["lee"]["brier"] == pytest.approx(0.04)
    assert rows["the model (belief.yaml)"]["settled"] == 2
    assert bayes.calibration(data)[0]["forecaster"] == "lee"   # best first

    assess.predict(data, "isolation", 0.5, "pat")              # settled, so a new one may open
    assess.apply_probe(data, isolation.run(target_for(fixed_server)), "e2.json")
    assert data["predictions"][-1]["outcome"] == "clean"


def test_prediction_validation():
    data = assess.new("demo", "L0", PROF)
    with pytest.raises(ValueError):
        assess.predict(data, "isolation", 1.5, "pat")
    with pytest.raises(ValueError):
        assess.predict(data, "isolation", 0.5, " ")


def test_cli_predict_and_calibration(tmp_path, fixed_server, capsys):
    import yaml

    a = str(tmp_path / "a.yaml")
    t = tmp_path / "t.yaml"
    t.write_text(yaml.safe_dump(target_for(fixed_server)))
    assert main(["init", "--product", "x", "--level", "L1", "-o", a]) == 0
    assert main(["calibration", a]) == 0
    assert "no settled predictions" in capsys.readouterr().out
    assert main(["predict", "isolation", "0.7", "--by", "pat", "-a", a]) == 0
    assert main(["predict", "isolation", "0.7", "--by", "pat", "-a", a]) == 2
    assert main(["probe", "isolation", "--config", str(t), "-a", a, "--evidence-dir", str(tmp_path / "ev")]) == 0
    capsys.readouterr()
    assert main(["calibration", a]) == 0
    out = capsys.readouterr().out
    assert "pat" in out and "0.090" in out and "Fewer than 20" in out
