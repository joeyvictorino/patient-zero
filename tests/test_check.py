"""`pz check`: the zero-setup scan, its outputs, and the agent-facing server."""
import base64
import io
import json
import os

import pytest
import yaml

from patient_zero import check, mcp
from patient_zero.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE_KEY = "sk-proj-" + "a1B2" * 12          # shaped like a key, built here so no secret sits in the repository


def write(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return str(tmp_path)


def rules_of(result):
    return {i.rule for i in result.issues}


@pytest.fixture
def vibe(tmp_path):
    service_role = ".".join(base64.urlsafe_b64encode(json.dumps(part).encode()).decode().rstrip("=")
                            for part in ({"alg": "HS256"}, {"role": "service_role", "iss": "supabase"}, {"sig": "x" * 12}))
    return write(tmp_path, {
        "src/ai.ts": 'import OpenAI from "openai";\n'
                     "const c = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });\n"
                     'console.log("summarizing", patient.name);\n'
                     'console.log("done");\n'
                     f'const admin = "{service_role}";\n',
        "src/track.js": 'posthog.init("x");\ngtag("config", "G-1");\nconst rec = new MediaRecorder(stream);\n',
        "api/main.py": 'import requests\napp.add_middleware(CORS, allow_origins=["*"])\nrequests.get(url, verify=False)\n',
        ".env": f"OPENAI_API_KEY={FAKE_KEY}\n",
        ".env.example": "OPENAI_API_KEY=your-key-here\n",
        "supabase/migrations/1.sql": "create table notes (id int, body text);\n",
        "docker-compose.yml": "services:\n  db:\n    image: postgres:16\n    ports: ['5432:5432']\n",
        "tests/fixture.js": 'posthog.capture("in a test");\n',
        "node_modules/x/index.js": 'fbq("track");\n',
    })


def test_check_finds_the_common_mistakes_and_never_prints_a_secret(vibe):
    result = check.run(vibe)
    assert rules_of(result) >= {
        "browser-model-key", "browser-model-call", "secret-openai-key", "secret-supabase-service-role", "env-file-committed",
        "model-provider-unlisted", "tracker-session-replay", "tracker-analytics", "audio-capture", "cors-wildcard",
        "tls-checks-off", "patient-data-in-logs", "rls-probe", "stack-probe",
    }
    assert result.failed("high") and result.worst() == "critical"
    text = check.render_text(result)
    assert FAKE_KEY not in text and FAKE_KEY not in json.dumps(result.to_dict())
    assert "NOT READY for real patient data" in text and "A clean check is not a pass" in text
    assert "What this could not check" in text
    logs = [i for i in result.issues if i.rule == "patient-data-in-logs"]
    assert [(i.file, i.line) for i in logs] == [("src/ai.ts", 3)]            # the line that logs "done" is not flagged
    assert not any(i.file.startswith(("tests/", "node_modules/")) for i in result.issues)
    assert not any(i.file == ".env.example" for i in result.issues)
    assert any(i.file == "tests/fixture.js" for i in check.run(vibe, include_tests=True).issues)


def test_a_register_with_a_baa_clears_the_provider_finding_and_a_weak_entry_does_not(vibe, tmp_path):
    entry = {"host": "api.openai.com", "baa": True, "training_on_phi": "prohibited", "retention": "0 days"}
    (tmp_path / "register.yaml").write_text(yaml.safe_dump({"endpoints": [entry]}))
    result = check.run(vibe)
    assert result.register == "register.yaml" and not rules_of(result) & {"model-provider-unlisted", "model-provider-not-approved"}
    (tmp_path / "register.yaml").write_text(yaml.safe_dump({"endpoints": [{**entry, "baa": False}]}))
    weak = [i for i in check.run(vibe).issues if i.rule == "model-provider-not-approved"]
    assert len(weak) == 1 and "no BAA" in weak[0].title


def test_suppression_needs_a_marker_and_is_reported(tmp_path):
    root = write(tmp_path, {"app.js": 'posthog.init("k"); // pz:ignore marketing page only, no patients\n'})
    result = check.run(root)
    assert not result.issues and result.suppressed[0]["reason"].startswith("marketing page only")
    assert "1 line(s) were marked" in check.render_text(result)


def test_an_empty_folder_is_void_and_a_clean_one_is_not_a_pass(tmp_path, capsys):
    assert main(["check", str(tmp_path)]) == 2
    assert "VOID" in capsys.readouterr().out
    write(tmp_path, {"app.py": "print('hello')\n"})
    assert main(["check", str(tmp_path)]) == 0
    assert "Nothing found. That is not a pass" in capsys.readouterr().out


def test_cli_outputs_and_thresholds(vibe, tmp_path, capsys):
    assert main(["check", vibe]) == 1
    capsys.readouterr()
    assert main(["check", vibe, "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["files_scanned"] > 0 and data["not_checked"] and data["worst"] == "critical"
    out = str(tmp_path / "out.sarif")
    main(["check", vibe, "--sarif", "-o", out])
    sarif = json.load(open(out))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "patient-zero"
    assert {r["ruleId"] for r in run["results"]} == {r["id"] for r in run["tool"]["driver"]["rules"]}
    low = tmp_path / "low"
    write(low, {"a.py": "import sentry_sdk\n"})
    assert main(["check", str(low)]) == 0 and main(["check", str(low), "--fail-on", "low"]) == 1


def test_this_repository_checks_clean():
    result = check.run(ROOT)
    assert result.files > 50 and [f"{i.rule} {i.file}:{i.line}" for i in result.issues] == []


def test_rules_file_is_well_formed():
    rules = check.load_rules()
    controls = {c.id for c in __import__("patient_zero.profile", fromlist=["x"]).load().controls}
    specs = rules["line_rules"] + [rules["log_rule"], rules["secret"], rules["service_role"], rules["env_file"]]
    for spec in specs:
        assert spec["severity"] in check.SEVERITIES and spec["control"] in controls
        for key in ("title", "why", "fix"):
            assert spec[key].strip()
        assert "compliant" not in (spec["title"] + spec["fix"]).lower()
    assert len({r["id"] for r in rules["line_rules"]}) == len(rules["line_rules"])
    assert len(rules["blind_spots"]) >= 4


# --- MCP server ---------------------------------------------------------------

def rpc(method, params=None, msg_id=1):
    return mcp.handle({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})


def test_mcp_lists_read_only_tools_and_runs_the_check(vibe):
    init = rpc("initialize")["result"]
    assert init["serverInfo"]["name"] == "patient-zero" and "Never tell the user the app is HIPAA compliant" in init["instructions"]
    tools = rpc("tools/list")["result"]["tools"]
    assert {t["name"] for t in tools} == set(mcp.TOOLS)
    assert not any(word in t["name"] for t in tools for word in ("set", "seal", "sign", "probe", "write"))
    reply = rpc("tools/call", {"name": "pz_check", "arguments": {"path": vibe}})["result"]
    assert not reply["isError"] and json.loads(reply["content"][0]["text"])["worst"] == "critical"
    explain = json.loads(rpc("tools/call", {"name": "pz_explain", "arguments": {"control": "consent-2"}})["result"]["content"][0]["text"])
    assert explain["id"] == "CONSENT-2" and explain["question_a_buyer_asks"].endswith("?")
    call = rpc("tools/call", {"name": "pz_scan_text", "arguments": {"text": "Patient John, SSN 123-45-6789"}})
    scanned = json.loads(call["result"]["content"][0]["text"])
    assert scanned["likely_patient_data"] and "123-45-6789" not in scanned["redacted"]


def test_mcp_errors_are_answers_not_crashes():
    assert rpc("tools/call", {"name": "pz_explain", "arguments": {"control": "NOPE-9"}})["result"]["isError"]
    assert rpc("tools/call", {"name": "nope"})["error"]["code"] == -32602
    assert rpc("no/such/method")["error"]["code"] == -32601
    assert mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    out = io.StringIO()
    mcp.serve(io.StringIO('not json\n\n{"jsonrpc":"2.0","id":7,"method":"ping"}\n'), out)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert replies[0]["error"]["code"] == -32700 and replies[1] == {"jsonrpc": "2.0", "id": 7, "result": {}}


# --- integration files --------------------------------------------------------

def test_integration_files_are_well_formed():
    action = yaml.safe_load(open(os.path.join(ROOT, "action.yml")))
    assert action["runs"]["using"] == "composite" and "fail-on" in action["inputs"]
    scripts = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
    assert "${{" not in scripts, "inputs must reach the shell through env, never by interpolation"
    hooks = yaml.safe_load(open(os.path.join(ROOT, ".pre-commit-hooks.yaml")))
    assert hooks[0]["id"] == "patient-zero-check" and hooks[0]["entry"].startswith("pz check")
    config = json.load(open(os.path.join(ROOT, "integrations", "mcp.json")))
    assert config["mcpServers"]["patient-zero"] == {"command": "pz", "args": ["mcp"]}
    skill = open(os.path.join(ROOT, "integrations", "claude-code", "skills", "patient-zero", "SKILL.md")).read()
    front = yaml.safe_load(skill.split("---")[1])
    assert front["name"] == "patient-zero" and len(front["description"]) < 1024
    for text in (skill, open(os.path.join(ROOT, "integrations", "AGENTS.md")).read()):
        assert "pz check ." in text and "compliant" in text and "pz:ignore" in text
