"""`pz check`: point it at a folder, get the mistakes to fix first, in plain language.

No target file, no running app, no account, no network. It reads the files in
a project and looks for the mistakes that show up again and again in AI-built
health apps: keys in the code, a model company with no agreement on file,
trackers, patient data in logs, an open database, an exposed stack.

Three things it will not do:
  * call a clean result a pass. It looks for a short list of mistakes and
    cannot see the ones that matter most (who can read whose records).
  * print a secret it finds. Only the first characters are shown.
  * count a run that looked at nothing. That is void, not clean.

The rules are data: patient_zero/data/check_rules.yaml. Other packages can add
checks through the `patient_zero.checks` entry point group (see `plugins`).
"""
from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
import subprocess
import textwrap
from dataclasses import asdict, dataclass, field
from importlib import metadata, resources
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import yaml

from . import __version__
from .egress import load_register
from .probes import ProbeRefused
from .probes import rls as rls_probe
from .probes import stack as stack_probe

SEVERITIES = ("critical", "high", "medium", "low")
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".go", ".rb", ".php", ".java",
            ".kt", ".swift", ".cs", ".rs", ".html", ".htm", ".sh"}
CONFIG_EXT = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".tf", ".properties"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "dist", "build", ".next", ".nuxt", ".svelte-kit", "vendor",
             "__pycache__", "coverage", ".turbo", ".cache", "target", ".pytest_cache", ".mypy_cache", ".ruff_cache", "evidence"}
TEST_PARTS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "__fixtures__", "e2e", "cypress", "testdata"}
SKIP_NAMES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock", "Cargo.lock", "go.sum", "bun.lockb"}
ENV_EXAMPLES = (".example", ".sample", ".template", ".dist", ".defaults")
REGISTER_NAMES = ("register.yaml", "register.yml", "pz-register.yaml", "subprocessors.yaml")
MAX_BYTES = 512 * 1024
IGNORE_MARK = "pz:ignore"


@dataclass
class Issue:
    rule: str
    severity: str
    control: str
    title: str
    why: str
    fix: str
    file: str = ""
    line: int = 0
    detail: str = ""
    more: int = 0          # further lines in the same file that match the same rule


@dataclass
class CheckResult:
    root: str
    files: int = 0
    kinds: int = 0                                           # how many kinds of mistake were looked for
    issues: List[Issue] = field(default_factory=list)
    suppressed: List[Dict[str, Any]] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)         # checks that had nothing to look at
    register: Optional[str] = None

    @property
    def void(self) -> bool:
        return self.files == 0

    def worst(self) -> Optional[str]:
        ranks = [SEVERITIES.index(i.severity) for i in self.issues]
        return SEVERITIES[min(ranks)] if ranks else None

    def failed(self, threshold: str = "medium") -> bool:
        limit = SEVERITIES.index(threshold)
        return any(SEVERITIES.index(i.severity) <= limit for i in self.issues)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "patient-zero", "version": __version__, "root": self.root, "files_scanned": self.files,
            "kinds_of_mistake": self.kinds, "void": self.void, "worst": self.worst(), "register": self.register,
            "issues": [asdict(i) for i in self.issues], "suppressed": self.suppressed, "skipped_checks": self.skipped,
            "not_checked": load_rules()["blind_spots"],
            "note": "A clean check is not a pass. It is not a HIPAA certification, and none exists.",
        }


def load_rules() -> Dict[str, Any]:
    return yaml.safe_load(resources.files("patient_zero").joinpath("data/check_rules.yaml").read_text("utf-8"))


def plugins() -> List[Tuple[str, Callable[[str, List[str]], Iterable[Issue]]]]:
    """Checks contributed by other installed packages.

    A plugin registers a callable under the `patient_zero.checks` entry point
    group. It receives (root, relative file paths) and returns Issues.
    """
    try:
        found = metadata.entry_points()
        group = found.select(group="patient_zero.checks") if hasattr(found, "select") else found.get("patient_zero.checks", [])
    except Exception:  # a broken plugin index must not stop the built-in checks
        return []
    return [(ep.name, ep.load()) for ep in group]


def list_files(root: str, include_tests: bool = False, exclude: Iterable[str] = ()) -> List[str]:
    """Project files worth reading, relative to root. Uses git when it can, so ignored files stay ignored."""
    rel: List[str] = []
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-co", "--exclude-standard", "-z"], capture_output=True, timeout=30)
        if out.returncode == 0:
            rel = [p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]
    except (OSError, subprocess.SubprocessError):
        rel = []
    if not rel:
        for base, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            rel += [os.path.relpath(os.path.join(base, n), root) for n in names]
    keep = []
    for path in sorted(set(p.replace(os.sep, "/") for p in rel)):
        parts = path.split("/")
        if any(p in SKIP_DIRS for p in parts[:-1]) or parts[-1] in SKIP_NAMES:
            continue
        if not include_tests and (any(p.lower() in TEST_PARTS for p in parts[:-1]) or re.search(r"(^test_|[._]test\.|[._]spec\.)", parts[-1])):
            continue
        if any(fnmatch.fnmatch(path, pattern) for pattern in exclude):
            continue
        if parts[-1].endswith((".min.js", ".map", ".lock")):
            continue
        full = os.path.join(root, path)
        if os.path.isfile(full) and not os.path.islink(full) and os.path.getsize(full) <= MAX_BYTES:
            keep.append(path)
    return keep


def _kind(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    ext = os.path.splitext(name)[1].lower()
    if name == ".env" or name.startswith(".env."):
        return "env"
    if ext in CODE_EXT:
        return "code"
    if ext in CONFIG_EXT or name in ("Dockerfile", "Procfile"):
        return "config"
    return "other"


def _mask(secret: str) -> str:
    return secret[:6] + "..." + f" ({len(secret)} characters)"


def _is_service_role(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("role") == "service_role"


_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
_STRING = re.compile(r"""[fFrRbB]{0,2}(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`)""")
_INTERPOLATED = re.compile(r"\{([^{}]*)\}")


def _code_only(text: str) -> str:
    """A line with the words inside string literals removed, keeping only what is interpolated into them.

    A log line whose message merely contains the word "patient" logs no patient. One that interpolates
    a patient's field into the message does. tests/test_check.py has both cases.
    """
    return _STRING.sub(lambda m: " " + " ".join(_INTERPOLATED.findall(m.group(0))) + " ", text)
_ENV_VALUE = re.compile(r"^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|PWD|DSN|DATABASE_URL)[A-Z0-9_]*)"
                        r"\s*=\s*['\"]?([^\s'\"#]{8,})")
_COMMENT = re.compile(r"^\s*(?:#|//|/\*|\*|<!--|--\s)")
_NOT_A_SECRET = re.compile(r"(?i)example|placeholder|redacted|\.\.\.|x{6,}|abcdefgh|0123456|your[_-]")
_PLACEHOLDER = re.compile(r"(?i)^(?:your|xxx|changeme|change-me|example|placeholder|todo|<|\$\{|dummy|test|fake|sk-\.\.\.)")


def _issue(spec: Dict[str, Any], rule: str, file: str = "", line: int = 0, detail: str = "", **fmt: str) -> Issue:
    return Issue(rule, spec["severity"], spec["control"], spec["title"].format(**fmt), spec["why"].format(**fmt),
                 spec["fix"].format(**fmt), file, line, detail)


def find_register(root: str, files: List[str], explicit: Optional[str] = None) -> Optional[str]:
    if explicit:
        return explicit
    for path in files:
        if path.rsplit("/", 1)[-1] in REGISTER_NAMES and "example" not in path:
            return os.path.join(root, path)
    return None


def run(path: str = ".", register: Optional[str] = None, include_tests: bool = False, exclude: Iterable[str] = ()) -> CheckResult:
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise FileNotFoundError(f"{path} is not a directory")
    rules = load_rules()
    files = list_files(root, include_tests, exclude)
    result = CheckResult(root=root, files=len(files))
    line_rules = [(r, re.compile(r["pattern"], 0 if r.get("case") else re.I)) for r in rules["line_rules"]]
    secret_rules = [(r, re.compile(r["pattern"])) for r in rules["secret_rules"]]
    providers = [(p, re.compile(p["pattern"], re.I)) for p in rules["providers"]]
    log_call = re.compile(rules["log_rule"]["call"])
    log_words = re.compile(rules["log_rule"]["words"], re.I)
    result.kinds = len(line_rules) + 5      # plus secrets, service role key, .env file, logs, model providers
    seen_providers: Dict[str, Tuple[str, int]] = {}

    def add(issue: Issue, text: str) -> None:
        if IGNORE_MARK in text:
            reason = text.split(IGNORE_MARK, 1)[1].strip(" :*/-#>")
            result.suppressed.append({"rule": issue.rule, "file": issue.file, "line": issue.line, "reason": reason})
        else:
            result.issues.append(issue)

    for rel in files:
        kind = _kind(rel)
        if kind == "other":
            continue
        try:
            with open(os.path.join(root, rel), "r", encoding="utf-8", errors="strict") as fh:
                whole = fh.read()
        except (UnicodeDecodeError, OSError):
            continue
        lines = whole.splitlines()
        name = rel.rsplit("/", 1)[-1]
        if kind == "env" and not name.endswith(ENV_EXAMPLES):
            real = [m for m in map(_ENV_VALUE.match, lines) if m and not _PLACEHOLDER.match(m.group(2))]
            if real:
                add(_issue(rules["env_file"], "env-file-committed", rel, 0, f"{len(real)} value(s), such as {real[0].group(1)}"), "")
        # Cheap test first: a rule's hints are plain text every match contains. Most files contain none, and no pattern runs on them.
        lowered = whole.lower()

        def hinted(spec: Dict[str, Any], text: str = lowered) -> bool:
            return not spec.get("hints") or any(h in text for h in spec["hints"])

        live_secrets = [(spec, pattern) for spec, pattern in secret_rules if spec.get("hint", "") in whole]
        live_lines = [(spec, pattern) for spec, pattern in line_rules
                      if not (spec["files"] == "code" and kind != "code") and not (spec["files"] == "config" and kind != "config")
                      and hinted(spec)]
        has_jwt = "eyJ" in whole
        has_log = kind == "code" and hinted(rules["log_rule"])
        live_providers = [(spec, pattern) for spec, pattern in providers
                          if kind == "code" and spec["name"] not in seen_providers and hinted(spec)]
        if not (live_secrets or live_lines or has_jwt or has_log or live_providers):
            continue
        seen_in_file: Dict[str, Issue] = {}
        for number, text in enumerate(lines, 1):
            if len(text) > 2000:
                continue
            commented = bool(_COMMENT.match(text)) and IGNORE_MARK not in text
            for spec, pattern in live_secrets:
                m = pattern.search(text)
                if m and not _PLACEHOLDER.match(m.group(0)[3:]) and not _NOT_A_SECRET.search(text):
                    add(_issue(rules["secret"], f"secret-{spec['id']}", rel, number, f"{spec['what']}: {_mask(m.group(0))}"), text)
                    break
            if has_jwt:
                for m in _JWT.finditer(text):
                    if _is_service_role(m.group(0)):
                        add(_issue(rules["service_role"], "secret-supabase-service-role", rel, number, _mask(m.group(0))), text)
            if commented:
                continue          # a commented-out line does nothing; secrets above are the exception, a key in a comment still leaks
            for spec, pattern in live_lines:
                if pattern.search(text):
                    first = seen_in_file.get(spec["id"])
                    if first is None or IGNORE_MARK in text:
                        issue = _issue(spec, spec["id"], rel, number)
                        add(issue, text)
                        if IGNORE_MARK not in text:
                            seen_in_file[spec["id"]] = issue
                    else:               # one finding per rule per file; say how many more lines there are
                        first.more += 1
                        first.detail = f"and {first.more} more line(s) in this file"
            if has_log:
                call = log_call.search(text)
                if call and log_words.search(_code_only(text[call.end():])):
                    add(_issue(rules["log_rule"], rules["log_rule"]["id"], rel, number), text)
            for spec, pattern in live_providers:
                if spec["name"] not in seen_providers and pattern.search(text) and IGNORE_MARK not in text:
                    seen_providers[spec["name"]] = (rel, number)

    # Model providers against the register of who may receive patient data.
    register_path = find_register(root, files, register)
    endpoints = load_register(register_path) if register_path else []
    result.register = os.path.relpath(register_path, root) if register_path else None
    for spec, _ in providers:
        if spec["name"] not in seen_providers:
            continue
        rel, number = seen_providers[spec["name"]]
        entry = next((e for e in endpoints if fnmatch.fnmatch(spec["host"], e.host)), None)
        if entry is None:
            result.issues.append(_issue({**rules["provider"]["unlisted"], "control": rules["provider"]["control"]}, "model-provider-unlisted",
                                        rel, number, name=spec["name"], host=spec["host"]))
        elif not entry.approved():
            result.issues.append(_issue({**rules["provider"]["problem"], "control": rules["provider"]["control"]}, "model-provider-not-approved",
                                        rel, number, name=spec["name"], host=spec["host"], problems=", ".join(entry.problems())))

    # The two static probes, when there is something for them to read.
    plain = {
        "stack": ("Part of the stack is open to the network",
                  "A database, model server or admin tool that listens on every network interface can be reached by anyone "
                  "who can reach the machine.",
                  "Publish it on 127.0.0.1 only, or put it behind the app, and remove privileged settings."),
        "rls": ("A database table has no per-patient or per-clinic access rule",
                "Without row level security, any signed-in user, and often any visitor holding the public key, can read every row in the table.",
                "Enable row level security on the table and add a policy that limits rows to their owner. "
                "A policy of USING (true) lets everyone through."),
    }
    # Hand the probes the same file list everything else used, so ignored, excluded and test files stay out.
    compose = [os.path.join(root, f) for f in files
               if re.fullmatch(r"(?:docker-)?compose[^/]*\.ya?ml", f.rsplit("/", 1)[-1])]
    sql = [os.path.join(root, f) for f in files if f.lower().endswith(".sql")]
    for probe, module, chosen in (("stack", stack_probe, compose), ("rls", rls_probe, sql)):
        try:
            findings = module.run(root, chosen).findings
        except ProbeRefused:
            result.skipped.append(probe)
            continue
        result.kinds += 1
        title, why, fix = plain[probe]
        for f in findings:
            result.issues.append(Issue(f"{probe}-probe", f.severity, f.control, title, why, fix, detail=f"{f.title}: {f.detail}".rstrip(": ")))

    for _name, plugin in plugins():
        result.kinds += 1
        for issue in plugin(root, list(files)):
            result.issues.append(issue)

    result.issues.sort(key=lambda i: (SEVERITIES.index(i.severity), i.rule, i.file, i.line))
    return result


def grouped(result: CheckResult) -> List[Dict[str, Any]]:
    """One entry per kind of mistake, worst first, with every place it was seen."""
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for issue in result.issues:
        g = groups.setdefault((issue.rule, issue.title), {"issue": issue, "places": []})
        where = f"{issue.file}:{issue.line}" if issue.line else issue.file
        g["places"].append(" ".join(x for x in (where, issue.detail) if x))
    return list(groups.values())


def render_text(result: CheckResult, top: int = 3, width: int = 100) -> str:
    rules = load_rules()
    lines = [f"patient-zero check: {result.root}"]
    if result.void:
        return "\n".join(lines + ["VOID: no files to read here. This is not a clean result."]) + "\n"
    lines += [f"Read {result.files} files, looking for {result.kinds} kinds of mistake.", ""]
    groups = grouped(result)

    def show(group: Dict[str, Any], number: Optional[int] = None) -> None:
        issue = group["issue"]
        lead = f"{number}. " if number else "-  "
        lines.append(f"{lead}[{issue.severity.upper()}] {issue.title}  ({issue.control})")
        for place in group["places"][:3]:
            if place:
                lines.append(f"     {place}")
        if len(group["places"]) > 3:
            lines.append(f"     and {len(group['places']) - 3} more place(s)")
        for label, text in (("Why it matters", issue.why), ("Fix", issue.fix)):
            lines.extend(textwrap.wrap(f"{label}: {text}", width=width, initial_indent="     ", subsequent_indent="       "))
        lines.append("")

    if not groups:
        lines += ["Nothing found. That is not a pass: this looks for a short list of common mistakes.", ""]
    else:
        serious = result.failed("high")
        lines.append(("NOT READY for real patient data. " if serious else "") + f"{len(groups)} thing(s) to fix" +
                     (f", starting with these {min(top, len(groups))}:" if len(groups) > top else ":"))
        lines.append("")
        for n, group in enumerate(groups[:top], 1):
            show(group, n)
        if len(groups) > top:
            lines += ["Also found:", ""]
            for group in groups[top:]:
                show(group)
    if result.suppressed:
        lines += [f"{len(result.suppressed)} line(s) were marked `{IGNORE_MARK}` and skipped. `--json` lists them with their reasons.", ""]
    lines.append("What this could not check:")
    lines += [f"  - {item}" for item in rules["blind_spots"]]
    lines += ["", "Next: `pz init --product \"...\" --level L1` starts a full assessment, and `pz next` says what to test first.",
              "A clean check is not a pass, and this is not a HIPAA certification. None exists."]
    return "\n".join(lines) + "\n"


def to_sarif(result: CheckResult) -> Dict[str, Any]:
    """SARIF 2.1.0, so findings show up in GitHub code scanning and editors."""
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for issue in result.issues:
        rules.setdefault(issue.rule, {
            "id": issue.rule, "name": issue.rule, "shortDescription": {"text": issue.title},
            "fullDescription": {"text": issue.why}, "help": {"text": issue.fix},
            "properties": {"control": issue.control, "severity": issue.severity},
        })
        entry: Dict[str, Any] = {"ruleId": issue.rule, "level": level[issue.severity],
                                 "message": {"text": f"{issue.title}. {issue.why} Fix: {issue.fix}" + (f" ({issue.detail})" if issue.detail else "")}}
        if issue.file:
            entry["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": issue.file},
                                                        "region": {"startLine": max(issue.line, 1)}}}]
        results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "patient-zero", "version": __version__,
                                      "informationUri": "https://github.com/joeyvictorino/patient-zero", "rules": list(rules.values())}},
                  "results": results}],
    }
