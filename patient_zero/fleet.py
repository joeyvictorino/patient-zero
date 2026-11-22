"""Many sealed reports at once: a clinic's vendors, or a coalition's cohort.

`pz vendors <folder>` reads every bundle in a folder, verifies each one, and
answers the questions a buyer or a convening body actually has:

  * a clinic: which of our vendors' reports are current, verified, co-signed
    by someone independent, and failing nothing?
  * a coalition or sandbox: across everyone taking part, which safeguards fail
    most often and which does nobody confirm? That is where shared effort,
    training or policy would do the most good.

With `anonymize`, products become "Product A", "Product B", so a cohort can
publish its picture without ranking its members. A bundle that does not verify
is listed as such and left out of every count.
"""
from __future__ import annotations

import base64
import glob
import json
import os
from typing import Any, Dict, List, Optional

import yaml

from . import buyer, seal
from . import profile as profile_mod

STALE_DAYS = 365


def _assessment(packed: Dict[str, Any]) -> Dict[str, Any]:
    for path, data in (packed.get("files") or {}).items():
        if path.endswith((".yaml", ".yml")):
            try:
                doc = yaml.safe_load(base64.b64decode(data))
            except (ValueError, yaml.YAMLError):
                continue
            if isinstance(doc, dict) and "controls" in doc and "level" in doc:
                return doc
    return {}


def read(folder: str) -> List[Dict[str, Any]]:
    """One row per bundle file in the folder, verified or not."""
    rows = []
    for path in sorted(glob.glob(os.path.join(folder, "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                packed = json.load(fh)
        except (ValueError, OSError):
            continue
        if not isinstance(packed, dict) or packed.get("schema") != seal.BUNDLE_SCHEMA:
            continue
        problems, document = seal.verify_bundle(path)
        info = seal.describe(document) if document else {}
        summary = info.get("summary") or {}
        cosigners = info.get("cosigners") or []
        row: Dict[str, Any] = {
            "file": os.path.basename(path), "verified": not problems, "problems": problems,
            "product": info.get("product"), "level": info.get("level"), "sealed_at": info.get("sealed_at"),
            "age_days": info.get("age_days"), "signer": (info.get("signer") or {}).get("name"),
            "domain": (info.get("signer") or {}).get("domain"), "build": summary.get("build"),
            "independent_cosigners": sum(1 for c in cosigners if c.get("role") == "independent-assessor"),
            "summary": summary, "statuses": {},
        }
        if not problems:
            row["statuses"] = {cid: entry.get("status", "not_assessed") for cid, entry in (_assessment(packed).get("controls") or {}).items()}
        row["flags"] = flags(row)
        rows.append(row)
    return rows


def flags(row: Dict[str, Any]) -> List[str]:
    """What a buyer should raise with this vendor, in plain words."""
    if not row["verified"]:
        return ["DOES NOT VERIFY: do not rely on it; ask the vendor for a fresh bundle"]
    out = []
    summary = row["summary"]
    if row["age_days"] is not None and row["age_days"] > STALE_DAYS:
        out.append(f"sealed {seal.age_phrase(row['age_days'])}: ask for a current one")
    if summary.get("failed"):
        out.append(f"{summary['failed']} safeguard(s) failing: ask which, and the fix date")
    if not row["independent_cosigners"]:
        out.append("nobody independent has co-signed: this is the vendor's own account")
    if not row["domain"]:
        out.append("signer names no website: the key is not tied to the vendor")
    if summary and summary.get("confirmed", 0) == 0:
        out.append("no safeguard confirmed by a person yet")
    return out


def cohort(rows: List[Dict[str, Any]], profile: Optional[profile_mod.Profile] = None) -> Dict[str, Any]:
    """Across verified reports: how often each safeguard fails, and how often a person has confirmed it."""
    profile = profile or profile_mod.load()
    good = [r for r in rows if r["verified"]]
    per: Dict[str, Dict[str, int]] = {}
    for row in good:
        for cid, status in row["statuses"].items():
            slot = per.setdefault(cid, {"assessed_by": 0, "fail": 0, "pass": 0, "partial": 0, "not_assessed": 0})
            slot["assessed_by"] += 1
            if status in slot:
                slot[status] += 1
    known = {c.id for c in profile.controls}
    controls = [{"id": cid, **counts} for cid, counts in sorted(per.items()) if cid in known]
    return {
        "reports": len(rows), "verified": len(good), "not_verified": len(rows) - len(good),
        "stale": sum(1 for r in good if (r["age_days"] or 0) > STALE_DAYS),
        "with_independent_cosigner": sum(1 for r in good if r["independent_cosigners"]),
        "with_failing": sum(1 for r in good if r["summary"].get("failed")),
        "most_often_failing": sorted([c for c in controls if c["fail"]], key=lambda c: (-c["fail"], c["id"]))[:10],
        "never_confirmed": [c["id"] for c in controls if c["pass"] == 0 and c["assessed_by"] == len(good) and good],
    }


def render(rows: List[Dict[str, Any]], anonymize: bool = False) -> str:
    """Markdown: one table of reports, then the cohort picture."""
    plain = buyer.load_plain()
    stats = cohort(rows)
    lines = ["# Sealed reports" + (" (anonymized)" if anonymize else ""), "",
             f"{stats['reports']} report(s) read, {stats['verified']} verified, {stats['not_verified']} did not verify. "
             f"{stats['with_failing']} have a failing safeguard, {stats['with_independent_cosigner']} are co-signed by an independent "
             f"assessor, {stats['stale']} are more than a year old.", "",
             "| Product | Level | Sealed | Confirmed by a person | Tested clean only | Failing | Independent co-signer | To raise |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for index, row in enumerate(rows):
        name = f"Product {chr(ord('A') + index % 26)}{index // 26 or ''}" if anonymize else (row["product"] or row["file"])
        s = row["summary"]
        if not row["verified"]:
            lines.append(f"| {name} | | | | | | | {row['flags'][0]} |")
            continue
        lines.append(f"| {name} | {row['level']} | {seal.age_phrase(row['age_days'])} | {s.get('confirmed', '?')} of {s.get('controls', '?')} | "
                     f"{s.get('tested_clean_only', '?')} | {s.get('failed', '?')} | {'yes' if row['independent_cosigners'] else 'no'} | "
                     f"{'; '.join(row['flags']) or 'nothing'} |")
    if stats["most_often_failing"]:
        lines += ["", "## Failing most often", "", "| Safeguard | In plain words | Failing in |", "| --- | --- | --- |"]
        for c in stats["most_often_failing"]:
            lines.append(f"| {c['id']} | {plain.get(c['id'], {}).get('plain', '')} | {c['fail']} of {c['assessed_by']} |")
    if stats["never_confirmed"]:
        shown = stats["never_confirmed"][:12]
        lines += ["", "## Confirmed by nobody", "",
                  f"No report has a person confirming these {len(stats['never_confirmed'])} safeguard(s)"
                  + (f" (first {len(shown)} shown)" if len(shown) < len(stats["never_confirmed"]) else "") + ":", ""]
        lines += [f"- {cid}: {plain.get(cid, {}).get('plain', '')}" for cid in shown]
    lines += ["", "This table reports what each vendor signed. It does not show the claims are true, it ranks nobody, and nothing in it "
              "means compliant or certified."]
    return "\n".join(lines) + "\n"
