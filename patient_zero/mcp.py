"""`pz mcp`: patient-zero as a Model Context Protocol server over stdio.

A coding agent that is building a health app can call these tools while it
works, instead of waiting for a person to remember to run a scan. Standard
library only, newline-delimited JSON-RPC 2.0, no network.

Every tool is read-only: nothing here edits a project, records a pass or
signs anything. Those acts belong to a person.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Callable, Dict, IO, Optional

from . import __version__, assess, bayes, buyer, check, phi
from . import profile as profile_mod

PROTOCOL = "2024-11-05"
NOT_A_PASS = "A clean result is not a pass, and patient-zero is not a HIPAA certification. A person decides what is ready."


def _check(args: Dict[str, Any]) -> str:
    result = check.run(args.get("path") or ".", include_tests=bool(args.get("include_tests")))
    return json.dumps(result.to_dict(), indent=1)


def _controls(args: Dict[str, Any]) -> str:
    prof = profile_mod.load()
    controls = prof.for_level(args["level"]) if args.get("level") else prof.controls
    if args.get("family"):
        controls = [c for c in controls if c.family == str(args["family"]).upper()]
    return "\n".join(f"{c.id} [{c.min_level}] {c.statement}" for c in controls) + f"\n\n{len(controls)} controls. {NOT_A_PASS}"


def _explain(args: Dict[str, Any]) -> str:
    prof = profile_mod.load()
    control = prof.get(str(args["control"]).upper())
    plain = buyer.load_plain()[control.id]
    family = prof.families[control.family]
    return json.dumps({"id": control.id, "level": control.min_level, "family": family["name"], "statement": control.statement,
                       "in_plain_words": plain["plain"], "question_a_buyer_asks": plain["ask"], "proof_a_buyer_expects": plain["proof"],
                       "hipaa": family.get("hipaa", [])}, indent=1)


def _scan_text(args: Dict[str, Any]) -> str:
    findings = phi.scan(str(args["text"]))
    kinds: Dict[str, int] = {}
    for f in findings:
        kinds[f.kind] = kinds.get(f.kind, 0) + 1
    return json.dumps({"likely_patient_data": bool(findings), "kinds": kinds, "redacted": phi.redact(str(args["text"])),
                       "note": "Heuristic. It misses things. Use made-up data in prompts, tests and logs."}, indent=1)


def _questionnaire(args: Dict[str, Any]) -> str:
    return buyer.questionnaire(profile_mod.load(), args.get("level") or "L1", args.get("overlay"))


def _status(args: Dict[str, Any]) -> str:
    prof = profile_mod.load()
    data = assess.load(args.get("assessment") or "assessment.yaml")
    actions = bayes.next_actions(data, prof, bayes.load_model(), top=5)
    return buyer.executive_summary(data, prof) + "\nWhat to test next:\n" + "\n".join(f"  {a['control']}: {a['action']}" for a in actions)


def _tool(name: str, description: str, properties: Dict[str, Any], required: Optional[list] = None) -> Dict[str, Any]:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties, "required": required or []}}


TOOLS: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "pz_check": _check, "pz_controls": _controls, "pz_explain": _explain, "pz_scan_text": _scan_text,
    "pz_questionnaire": _questionnaire, "pz_status": _status,
}
TOOL_LIST = [
    _tool("pz_check", "Read a project folder and return the mistakes to fix first before it touches patient data: keys in code, a model "
          "company with no agreement on file, trackers, patient data in logs, open database tables, exposed services. Run it after "
          "adding a model call, a database table, analytics or auth. " + NOT_A_PASS,
          {"path": {"type": "string", "description": "project folder, default the current directory"},
           "include_tests": {"type": "boolean"}}),
    _tool("pz_controls", "List the safeguards in the open PHI safeguard profile, optionally for one level (L0, L1, L2) or family.",
          {"level": {"type": "string", "enum": list(profile_mod.LEVELS)}, "family": {"type": "string"}}),
    _tool("pz_explain", "Explain one safeguard: the requirement, what it means in plain words, and what proof a buyer expects.",
          {"control": {"type": "string", "description": "a control id such as GATE-3 or CONSENT-2"}}, ["control"]),
    _tool("pz_scan_text", "Check a piece of text for likely patient data before it goes into a prompt, a test fixture or a log, and "
          "return it redacted.", {"text": {"type": "string"}}, ["text"]),
    _tool("pz_questionnaire", "The questions a clinic will ask a vendor, in plain language, with the proof each answer needs.",
          {"level": {"type": "string", "enum": list(profile_mod.LEVELS)}, "overlay": {"type": "string", "enum": buyer.overlays()}}),
    _tool("pz_status", "Summarize an assessment file in plain language and say what to test next.",
          {"assessment": {"type": "string", "description": "path, default assessment.yaml"}}),
]


def handle(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Answer one JSON-RPC message. Notifications get no answer."""
    method, msg_id = message.get("method"), message.get("id")
    if msg_id is None:
        return None

    def ok(result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    if method == "initialize":
        return ok({"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                   "serverInfo": {"name": "patient-zero", "version": __version__},
                   "instructions": "Use pz_check on the project whenever code that handles patient data changes. Fix what it finds, "
                                   "worst first. Never tell the user the app is HIPAA compliant: " + NOT_A_PASS})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOL_LIST})
    if method == "tools/call":
        params = message.get("params") or {}
        tool = TOOLS.get(params.get("name"))
        if tool is None:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32602, "message": f"unknown tool: {params.get('name')}"}}
        try:
            return ok({"content": [{"type": "text", "text": tool(params.get("arguments") or {})}], "isError": False})
        except Exception as exc:  # a tool error is an answer, not a crash
            return ok({"content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}], "isError": True})
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"method not found: {method}"}}


def serve(stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout) -> int:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            reply: Optional[Dict[str, Any]] = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            reply = handle(message) if isinstance(message, dict) else None
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
    return 0
