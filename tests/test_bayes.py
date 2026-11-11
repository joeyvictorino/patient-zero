import math
from datetime import date, timedelta

import pytest

from patient_zero import assess, bayes, html, profile
from patient_zero.cli import main
from patient_zero.demo import run as demo_run
from patient_zero.probes.common import ProbeResult

MODEL = bayes.load_model()
PROF = profile.load()
TODAY = date(2026, 11, 10)


def probe_obs(outcome, checks=10, probe="isolation", when=TODAY):
    return {"kind": "probe", "probe": probe, "outcome": outcome, "checks": checks, "date": when.isoformat()}


def entry(*observations):
    return {"status": "partial", "observations": list(observations)}


def p(e, control="GATE-3", today=TODAY):
    return bayes.posterior(MODEL, e, control, today)


def test_no_evidence_is_the_prior():
    assert p(entry()) == pytest.approx(MODEL["prior"])


def test_finding_collapses_belief_and_clean_run_raises_it_modestly():
    assert p(entry(probe_obs("finding"))) < 0.05
    clean = p(entry(probe_obs("clean", checks=10)))
    assert 0.5 < clean < 0.75  # a clean probe is evidence, never proof


def test_more_checks_mean_more_belief_but_coverage_caps_it():
    few, many, huge = (p(entry(probe_obs("clean", checks=n))) for n in (2, 20, 2000))
    assert few < many <= huge
    cap = 1 / (1 + (1 - MODEL["coverage"]["isolation"]["GATE-3"]) / (1 - MODEL["false_positive"]))
    assert huge == pytest.approx(cap, abs=1e-3)


def test_zero_checks_is_no_evidence():
    assert p(entry(probe_obs("clean", checks=0))) == pytest.approx(0.5, abs=0.01)


def test_probe_that_cannot_see_a_control_says_nothing_about_it():
    assert p(entry(probe_obs("clean", checks=50)), control="BASE-1") == pytest.approx(0.5, abs=0.01)


def test_rerunning_a_probe_replaces_instead_of_stacking():
    once = p(entry(probe_obs("clean")))
    thrice = p(entry(probe_obs("clean"), probe_obs("clean"), probe_obs("clean")))
    assert once == pytest.approx(thrice)
    fixed = p(entry(probe_obs("finding"), probe_obs("clean")))
    assert fixed == pytest.approx(once)


def test_independent_attestation_counts_for_more_than_self():
    self_ = p(entry({"kind": "attestation", "by": "self", "outcome": "pass", "date": TODAY.isoformat()}))
    indep = p(entry({"kind": "attestation", "by": "independent", "outcome": "pass", "date": TODAY.isoformat()}))
    assert 0.5 < self_ < indep


def test_evidence_decays_toward_the_prior():
    obs = {"kind": "attestation", "by": "independent", "outcome": "pass", "date": TODAY.isoformat()}
    fresh = p(entry(obs))
    half = p(entry(obs), today=TODAY + timedelta(days=MODEL["half_life_days"]))
    ancient = p(entry(obs), today=TODAY + timedelta(days=3650))
    assert fresh > half > ancient
    assert ancient == pytest.approx(0.5, abs=0.01)
    # at one half-life the log-odds are exactly halved
    lo = lambda x: math.log(x / (1 - x))
    assert lo(half) == pytest.approx(lo(fresh) / 2, rel=1e-6)


def test_wall_of_green_ticks():
    rows = [{"id": f"C-{i}", "p": 0.9} for i in range(35)]
    ready = bayes.readiness(rows)
    assert ready["p_all_hold"] == pytest.approx(0.9 ** 35)
    assert ready["p_all_hold"] < 0.03
    assert ready["expected_open"] == pytest.approx(3.5)


def test_beliefs_skip_not_applicable_and_read_old_files():
    data = assess.new("demo", "L0", PROF)
    assess.set_status(data, "GATE-5", "not_applicable", note="no free-text input")
    data["controls"]["GATE-1"] = {"status": "pass", "evidence": ["x"], "updated": TODAY.isoformat()}  # pre-ledger file
    rows = {r["id"]: r for r in bayes.beliefs(data, PROF, MODEL, TODAY)}
    assert "GATE-5" not in rows and len(rows) == 4
    assert rows["GATE-1"]["p"] > 0.5


def test_next_actions_prefer_cheap_informative_tests_and_respect_what_is_done():
    data = assess.new("demo", "L1", PROF)
    actions = bayes.next_actions(data, PROF, MODEL, TODAY, top=50)
    assert actions[0]["action"].startswith("run the") and actions[0]["cost"] == 1
    assert all(a["bits"] > 0 for a in actions)
    assert actions == sorted(actions, key=lambda a: a["bits_per_cost"], reverse=True)

    big = ProbeResult("isolation", ["GATE-3", "TEST-1"], "t")
    big.checks_for = {"GATE-3": 40, "TEST-1": 40}
    assess.apply_probe(data, big, "e.json")
    after = bayes.next_actions(data, PROF, MODEL, date.today(), top=200)
    assert not any(a["control"] == "GATE-3" and "isolation" in a["action"] for a in after)

    small = ProbeResult("egress", ["TRUST-1", "TRUST-2"], "t")
    small.checks_for = {"TRUST-2": 2, "TRUST-1": 1}
    assess.apply_probe(data, small, "e2.json")
    after = bayes.next_actions(data, PROF, MODEL, date.today(), top=200)
    assert any(a["control"] == "TRUST-2" and a["action"].startswith("widen the egress") for a in after)


def test_entropy_bounds():
    assert bayes.entropy(0.5) == pytest.approx(1.0)
    assert bayes.entropy(0.999999) < 0.001


def test_demo_runs_offline_and_shows_the_fix():
    lines = []
    assert demo_run.run(out=lines.append) == 0
    text = "\n".join(lines)
    assert "vulnerable build" in text and "patched build" in text
    assert "GATE-3: GET /api/workspaces/ws_a/clients returned tenant A's data to another tenant" in text
    assert "(x4)" in text and "AGENT-4" in text and "TRUST-2" in text and "LOG-2" in text
    patched = text.split("== patched build ==")[1]
    assert patched.count("clean") >= 4 and "finding" not in patched.split("belief after")[0]


def test_cli_belief_next_and_html(tmp_path, capsys):
    a = str(tmp_path / "assessment.yaml")
    assert main(["init", "--product", "Demo <App>", "--level", "L1", "-o", a]) == 0
    assert main(["set", "BASE-1", "pass", "--evidence", "mfa.png", "--independent", "-a", a]) == 0
    capsys.readouterr()
    assert main(["belief", a]) == 0
    out = capsys.readouterr().out
    assert "1 of 35 controls marked pass" in out and "BASE-1" in out
    assert main(["next", a, "--top", "3"]) == 0
    assert capsys.readouterr().out.count("bits") == 3
    page = str(tmp_path / "report.html")
    assert main(["report", a, "--html", "-o", page]) == 0
    doc = open(page).read()
    assert doc.startswith("<!doctype html>") and "Demo &lt;App&gt;" in doc and "<script" not in doc
    assert doc.count("class='row'") == 35
    assert html.render(assess.load(a), PROF, MODEL).count("belief it holds") == 35
