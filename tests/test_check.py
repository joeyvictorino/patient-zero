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
        "model-provider-unlisted", "tracker-analytics", "audio-capture", "cors-wildcard",
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
    result = check.run(ROOT, exclude=["examples/vibe-clinic/*"])       # that folder is wrong on purpose
    assert result.files > 50 and [f"{i.rule} {i.file}:{i.line}" for i in result.issues] == []


def test_the_example_app_shows_a_dozen_kinds_of_mistake_and_holds_no_real_secret():
    result = check.run(os.path.join(ROOT, "examples", "vibe-clinic"))
    assert len(check.grouped(result)) >= 12 and result.worst() == "critical"
    assert not any(i.rule.startswith("secret-") for i in result.issues)     # nothing shaped like a real provider key is committed


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


# --- every rule fires on a line written for it, so a hint can never hide a match ---

SAMPLES = {
    "browser-model-key": "const k = import.meta.env.VITE_ANTHROPIC_KEY",
    "browser-model-call": "new OpenAI({ dangerouslyAllowBrowser: true })",
    "tls-checks-off": "client := &tls.Config{InsecureSkipVerify: true}",
    "cors-wildcard": 'res.setHeader("Access-Control-Allow-Origin", "*")',
    "tracker-session-replay": 'import LogRocket from "logrocket"',
    "tracker-analytics": 'import { Analytics } from "@vercel/analytics/react"',
    "error-reporting": "Bugsnag.start()",
    "browser-storage": 'sessionStorage.setItem("jwt", token)',
    "audio-capture": "navigator.mediaDevices.getUserMedia({ audio: true })",
}
PROVIDER_SAMPLES = {
    "OpenAI": "from langchain_openai import ChatOpenAI", "Anthropic": 'import Anthropic from "@anthropic-ai/sdk"',
    "Google Gemini": 'import { GoogleGenAI } from "@google/genai"', "Groq": 'import Groq from "groq-sdk"',
    "Mistral": "from mistralai import Mistral", "Cohere": "import cohere", "Together AI": 'fetch("https://api.together.xyz/v1")',
    "OpenRouter": 'baseURL: "https://openrouter.ai/api/v1"', "DeepSeek": 'base_url="https://api.deepseek.com"',
    "xAI": 'base_url="https://api.x.ai/v1"', "Perplexity": 'fetch("https://api.perplexity.ai/chat")', "Replicate": "import replicate",
    "Hugging Face Inference": "client = InferenceClient()", "ElevenLabs": "from elevenlabs import play",
    "Deepgram": 'import { createClient } from "@deepgram/sdk"', "AssemblyAI": "import assemblyai as aai",
}


def test_every_line_rule_and_provider_fires_on_its_sample(tmp_path):
    rules = check.load_rules()
    assert set(SAMPLES) == {r["id"] for r in rules["line_rules"]} and set(PROVIDER_SAMPLES) == {p["name"] for p in rules["providers"]}
    for rule, line in SAMPLES.items():
        folder = tmp_path / rule
        write(folder, {"app.ts": line + "\n"})
        assert rule in rules_of(check.run(str(folder))), rule
    for name, line in PROVIDER_SAMPLES.items():
        folder = tmp_path / name.replace(" ", "-")
        write(folder, {"app.py": line + "\n"})
        titles = [i.title for i in check.run(str(folder)).issues if i.rule == "model-provider-unlisted"]
        assert any(name in t for t in titles), name
    for spec in rules["line_rules"] + rules["providers"] + [rules["log_rule"]]:
        assert all(h == h.lower() for h in spec.get("hints", [])), spec


def test_check_is_fast_enough_for_a_large_project(tmp_path):
    import time

    body = "def handler(request):\n    value = compute(request)\n    return respond(value)\n" * 400
    write(tmp_path, {f"pkg{n // 50}/module{n}.py": body for n in range(400)})
    started = time.time()
    result = check.run(str(tmp_path))
    assert result.files == 400 and not result.issues
    assert time.time() - started < 10, "400 files of ordinary code should take about a second"


def test_log_rule_looks_at_what_is_interpolated_not_at_the_words_in_the_message(tmp_path):
    root = write(tmp_path, {"a.py": 'print(f"patient-zero found {count} bundles")\nlogger.info("patient intake started")\n'
                                    'print(f"saved {patient.name}")\nlogger.info("note for %s", patient_id)\n',
                            "b.ts": "console.log(`loaded ${records.length} rows for the patient list`);\nconsole.log(`dx: ${diagnosis}`);\n"})
    hits = sorted((i.file, i.line) for i in check.run(root).issues if i.rule == "patient-data-in-logs")
    assert hits == [("a.py", 3), ("b.ts", 2)]


def test_false_positives_found_on_real_packages_stay_fixed(tmp_path):
    """Each line here was flagged when the check was first run on public packages. None is a real finding."""
    root = write(tmp_path, {
        "ui.py": "add_scrollbars=False\n"                                             # contains "rollbar"
                 'path = home / "analytics.jsonl"\n'                                   # not analytics.js
                 'dirname = "Flask-AppBuilder-Skeleton-AddOn-master"\n'                # "sk-" in the middle of a word
                 '"replicate": replicate_models,\n'                                    # a dictionary key, not an import
                 "# requests.get(url, verify=False)  left here as a warning\n"         # commented out
                 "// posthog.init('x')\n",
        "docs.json": '{"text": "My AWS secret key is AKIAIOSFODNN7EXAMPLE"}\n'         # the documented example key
                     '{"placeholder": "-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----"}\n',
        "db/1.sql": "-- create table if needed by hand\ncreate table if not exists notes (id int);\n"
                    "alter table notes enable row level security;\n",
    })
    assert [f"{i.rule} {i.file}:{i.line} {i.detail}" for i in check.run(root).issues] == []


def test_one_finding_per_rule_per_file_says_how_many_more(tmp_path):
    root = write(tmp_path, {"a.js": "mixpanel.track('a')\nmixpanel.track('b')\nmixpanel.track('c')\n", "b.js": "mixpanel.init('k')\n"})
    found = [i for i in check.run(root).issues if i.rule == "tracker-analytics"]
    assert [(i.file, i.line, i.more) for i in found] == [("a.js", 1, 2), ("b.js", 1, 0)]
    assert "and 2 more line(s) in this file" in check.render_text(check.run(root))


def test_a_real_key_in_a_comment_is_still_reported(tmp_path):
    root = write(tmp_path, {"a.py": f"# old key: {FAKE_KEY}\n"})
    assert rules_of(check.run(root)) == {"secret-openai-key"}
