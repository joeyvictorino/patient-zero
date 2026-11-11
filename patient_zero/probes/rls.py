"""Static probe: Postgres tables with no row level security (GATE-3).

Needs no running database: `pz probe rls --path supabase/migrations`

Row level security is how most Postgres-backed AI apps (Supabase and similar)
keep one tenant's rows from another. This reads SQL migrations in file-name
order and reports tables that end up without it, and policies that let
everyone through. It is a regex reading of SQL, not a parser: dynamic SQL,
tables made outside migrations and policies that are wrong in subtler ways
are out of its sight. Treat a clean result as weak evidence.
"""
from __future__ import annotations

import glob
import os
import re
from typing import Dict, List

from .common import ProbeRefused, ProbeResult

CONTROLS = ["GATE-3"]

_NAME = r'((?:"?[\w$]+"?\.)?"?[\w$]+"?)'
_CREATE = re.compile(rf"create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?{_NAME}", re.I)
_DROP = re.compile(rf"drop\s+table\s+(?:if\s+exists\s+)?{_NAME}", re.I)
_RLS = re.compile(rf"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{_NAME}\s+(enable|disable)\s+row\s+level\s+security", re.I)
_POLICY = re.compile(rf'create\s+policy\s+("[^"]+"|[\w$]+)\s+on\s+{_NAME}([^;]*);', re.I | re.S)
_OPEN = re.compile(r"(?:using|with\s+check)\s*\(\s*true\s*\)", re.I)
_COMMENTS = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
SYSTEM_SCHEMAS = {"auth", "storage", "extensions", "pg_catalog", "information_schema", "realtime", "vault", "graphql"}


def _normalize(name: str) -> str:
    name = name.replace('"', "").lower()
    return name if "." in name else f"public.{name}"


def sql_files(path: str) -> List[str]:
    if os.path.isfile(path):
        return [path]
    return sorted(glob.glob(os.path.join(path, "**", "*.sql"), recursive=True))


def run(path: str) -> ProbeResult:
    files = sql_files(path)
    if not files:
        raise ProbeRefused(f"no .sql files found at {path}")
    tables: Dict[str, bool] = {}          # table -> row level security enabled
    open_policies: Dict[str, List[str]] = {}
    for file in files:
        with open(file, "r", encoding="utf-8", errors="replace") as fh:
            sql = _COMMENTS.sub(" ", fh.read())
        events = [(m.start(), "create", m) for m in _CREATE.finditer(sql)]
        events += [(m.start(), "drop", m) for m in _DROP.finditer(sql)]
        events += [(m.start(), "rls", m) for m in _RLS.finditer(sql)]
        events += [(m.start(), "policy", m) for m in _POLICY.finditer(sql)]
        for _, kind, m in sorted(events, key=lambda e: e[0]):
            if kind == "create":
                tables.setdefault(_normalize(m.group(1)), False)
            elif kind == "drop":
                tables.pop(_normalize(m.group(1)), None)
                open_policies.pop(_normalize(m.group(1)), None)
            elif kind == "rls":
                name = _normalize(m.group(1))
                if name in tables:
                    tables[name] = m.group(2).lower() == "enable"
            elif _OPEN.search(m.group(3)):
                open_policies.setdefault(_normalize(m.group(2)), []).append(m.group(1).strip('"'))

    result = ProbeResult("rls", CONTROLS, os.path.abspath(path))
    for name in sorted(tables):
        if name.split(".")[0] in SYSTEM_SCHEMAS:
            continue
        result.tick("GATE-3")
        if not tables[name]:
            result.add("GATE-3", "high", f"table {name} has no row level security", "any role with table access reads every tenant's rows")
        for policy in open_policies.get(name, []):
            result.add("GATE-3", "high", f"policy '{policy}' on {name} lets every row through", "USING (true) or WITH CHECK (true)")
    if not result.checks:
        result.inconclusive.append("no application tables found in these migrations")
    return result
