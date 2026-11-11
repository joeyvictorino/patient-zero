"""Embedded mode, generated documents, known gaps, and the no-telemetry claim."""
import glob
import json
import os
import re
import socket

import pytest

from patient_zero import coverage, profile
from patient_zero.demo import run as demo_run
from patient_zero.embedded import assert_agent_contained, assert_isolated, check_isolation, wsgi_transport

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROF = profile.load()
CANARY = "wsgi-canary-7f3a"
TOKENS = {"tok-a": "ws_a", "tok-b": "ws_b"}


def make_wsgi_app(vulnerable):
    data = {"ws_a": {"clients": [{"note": CANARY}], "notes": []}, "ws_b": {"clients": [], "notes": []}}

    def app(environ, start_response):
        def reply(status, payload):
            body = json.dumps(payload).encode()
            start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]

        tenant = TOKENS.get(environ.get("HTTP_AUTHORIZATION", "").replace("Bearer ", ""))
        path, method = environ["PATH_INFO"], environ["REQUEST_METHOD"]
        m = re.fullmatch(r"/api/workspaces/(\w+)/(clients|notes)", path)
        if m and method == "GET":
            ws, kind = m.groups()
            if ws not in data:
                return reply("404 Not Found", {})
            if not vulnerable and tenant != ws:
                return reply("403 Forbidden" if tenant else "401 Unauthorized", {})
            return reply("200 OK", {kind: data[ws][kind]})
        if tenant is None:
            return reply("401 Unauthorized", {})
        body = json.loads(environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0)) or b"{}")
        if m and method == "POST" and m.group(1) == tenant:
            data[tenant]["notes"].append(body.get("text", ""))
            return reply("201 Created", {"ok": True})
        if path == "/api/agent/chat":
            if "summarize" in body.get("message", "").lower():
                last = data[tenant]["notes"][-1] if data[tenant]["notes"] else ""
                joined = re.search(r"joining '(\w+)' and '(\w+)'", last)
                return reply("200 OK", {"reply": joined.group(1) + joined.group(2) if vulnerable and joined else "noted"})
            scope = list(data) if vulnerable else [tenant]
            return reply("200 OK", {"reply": json.dumps([data[w]["clients"] for w in scope])})
        return reply("404 Not Found", {})

    return app


RESOURCES = ["/api/workspaces/ws_a/clients"]
AGENT = dict(endpoint="/api/agent/chat", canaries=[CANARY],
             injection={"seeds": [{"name": "note", "path": "/api/workspaces/ws_b/notes", "body": {"text": "{payload}"}}],
                        "trigger_prompt": "Summarize my most recent note."})


def test_embedded_isolation_on_a_bare_wsgi_app():
    result = assert_isolated(make_wsgi_app(False), "tok-a", "tok-b", RESOURCES, canary=CANARY)
    assert result.clean and result.checks_for["GATE-3"] == 2 and result.exchanges
    with pytest.raises(AssertionError, match="returned tenant A's data"):
        assert_isolated(make_wsgi_app(True), "tok-a", "tok-b", RESOURCES, canary=CANARY)


def test_embedded_fails_when_nothing_could_be_tested():
    with pytest.raises(AssertionError, match="tested nothing"):
        assert_isolated(make_wsgi_app(False), "tok-a", "tok-b", ["/api/workspaces/nope/clients"])


def test_embedded_agent_probe():
    assert assert_agent_contained(make_wsgi_app(False), "tok-a", "tok-b", **AGENT).clean
    with pytest.raises(AssertionError, match="MEM-1"):
        assert_agent_contained(make_wsgi_app(True), "tok-a", "tok-b", **AGENT)


class RequestsShaped:
    """Stands in for httpx, requests, Starlette and FastAPI test clients."""
    def __init__(self, app):
        self._send = wsgi_transport(app)

    def request(self, method, url, headers=None, json=None):
        status, text = self._send(method, url, headers or {}, json)
        return type("R", (), {"status_code": status, "text": text})()


class FlaskShaped:
    def __init__(self, app):
        self._send = wsgi_transport(app)

    def open(self, path, method="GET", headers=None, json=None):
        status, text = self._send(method, path, headers or {}, json)
        return type("R", (), {"status_code": status, "get_data": lambda self, as_text=False: text})()


@pytest.mark.parametrize("wrap", [RequestsShaped, FlaskShaped])
def test_embedded_with_framework_test_clients(wrap):
    assert check_isolation(wrap(make_wsgi_app(False)), "tok-a", "tok-b", RESOURCES, canary=CANARY).clean
    assert not check_isolation(wrap(make_wsgi_app(True)), "tok-a", "tok-b", RESOURCES, canary=CANARY).clean


def test_embedded_rejects_things_it_cannot_call():
    with pytest.raises(TypeError):
        check_isolation(42, "a", "b", RESOURCES)


# --- generated documents --------------------------------------------------------

def test_generated_documents_are_up_to_date():
    assert open(os.path.join(ROOT, "docs", "COVERAGE.md")).read() == coverage.markdown(PROF)
    assert open(os.path.join(ROOT, "docs", "PROFILE.md")).read() == coverage.profile_markdown(PROF)


def test_readme_numbers_match_the_code():
    s = coverage.summary(PROF)
    readme = open(os.path.join(ROOT, "README.md")).read()
    assert f"touch {s['probed']} of {s['controls']} controls" in readme
    assert f"The other {s['controls'] - s['probed']} need a person" in readme
    assert s["probes"] == 9 and "nine probes" in readme


def test_coverage_registry_names_real_things():
    ids = {c.id for c in PROF.controls}
    for mapping in (coverage.PROBE_CONTROLS, coverage.SAFEGUARD_CONTROLS):
        for name, controls in mapping.items():
            assert set(controls) <= ids, name
    for module in coverage.SAFEGUARD_CONTROLS:
        __import__(f"patient_zero.{module}")
    model_probes = set(__import__("patient_zero.bayes", fromlist=["x"]).load_model()["coverage"])
    assert model_probes == set(coverage.PROBE_CONTROLS)   # every probe has stated likelihoods, and nothing else does


# --- known gaps ---------------------------------------------------------------

def test_known_gap_files_are_well_formed():
    files = glob.glob(os.path.join(ROOT, "known-gaps", "*", "*.md"))
    assert len(files) >= 10
    for path in files:
        lines = open(path).read().splitlines()
        assert re.fullmatch(r"Severity: (HIGH|MEDIUM|LOW)", lines[0]), path
        assert re.fullmatch(r"Gap-Class: (missing|wrong|weak|unverified)", lines[1]), path
        assert lines[3].startswith("# "), path
        assert re.match(r"\d{8}-[a-z0-9-]+\.md$", os.path.basename(path)), path
    open_gaps = os.listdir(os.path.join(ROOT, "known-gaps", "things-that-do-not-work"))
    s = coverage.summary(PROF)
    unprobed = s["controls"] - s["probed"]
    words = {32: "thirty-two"}
    assert any(words.get(unprobed, str(unprobed)) in name for name in open_gaps), "update the no-probe gap file name"


# --- no telemetry -------------------------------------------------------------

def test_demo_opens_no_connection_beyond_loopback(monkeypatch):
    seen = []
    real_connect = socket.socket.connect

    def watching(self, address):
        seen.append(address)
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", watching)
    assert demo_run.run(out=lambda line: None) == 0
    assert seen, "the demo should have talked to its local app"
    assert all(str(addr[0]) in ("127.0.0.1", "::1", "localhost") for addr in seen)
