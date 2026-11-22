"""Synthetic patient records for pilots: obviously fake, repeatable, with canaries planted.

A pilot needs data that looks enough like a chart to exercise an app and can
never be mistaken for, or collide with, a real person. Every record here is
marked in ways a person and a program can both see:

  * names come from a short list of invented surnames ending in "-Synth"
  * social security numbers start with 900-999, a range that is never issued
  * phone numbers use 555-01xx, reserved for fiction
  * record numbers start with SYN, addresses are on "Example" streets, and
    email addresses end in .example
  * every record carries "synthetic": true

`generate` is seeded, so two people with the same seed get the same records.
Each tenant gets a canary string planted in one note, which is what the
isolation and agent probes look for on the other tenant's side.
"""
from __future__ import annotations

import csv
import io
import json
import random
from datetime import date, timedelta
from typing import Any, Dict, List

FIRST = ["Ana", "Ben", "Chen", "Dalia", "Emeka", "Farah", "Gus", "Hana", "Ivo", "Jun", "Kira", "Luis", "Mona", "Nico", "Ola",
         "Priya", "Quinn", "Rosa", "Sam", "Tala"]
LAST = ["Alder-Synth", "Birch-Synth", "Cedar-Synth", "Dune-Synth", "Ember-Synth", "Flint-Synth", "Grove-Synth", "Heron-Synth",
        "Isle-Synth", "Juniper-Synth"]
CONDITIONS = ["seasonal allergies", "type 2 diabetes", "hypertension", "asthma", "migraine", "lower back pain", "anxiety",
              "hypothyroidism", "acid reflux", "knee osteoarthritis"]
MEDICATIONS = ["cetirizine 10 mg", "metformin 500 mg", "lisinopril 10 mg", "albuterol inhaler", "sumatriptan 50 mg",
               "ibuprofen 400 mg", "sertraline 50 mg", "levothyroxine 50 mcg", "omeprazole 20 mg", "acetaminophen 500 mg"]
PLANS = ["Example Health Plan", "Sample Mutual", "Demo Care PPO"]
TODAY = date(2026, 1, 1)      # fixed, so ages and dates do not drift between runs


def canary(tenant: str, seed: int) -> str:
    return f"PZ-CANARY-{tenant.upper()}-{random.Random(f'{seed}:{tenant}').getrandbits(24):06x}"


def generate(patients: int = 25, seed: int = 1, tenants: int = 2) -> Dict[str, Any]:
    """Records split across tenants (clinics), each tenant with one canary planted in a visit note."""
    if patients < 1 or not 1 <= tenants <= 26:
        raise ValueError("need at least one patient and between 1 and 26 tenants")
    rng = random.Random(seed)
    out: Dict[str, Any] = {"synthetic": True, "seed": seed, "notice": "Made-up records for testing. No real person is described.",
                           "tenants": []}
    names = [chr(ord("a") + i) for i in range(tenants)]
    for index, name in enumerate(names):
        records: List[Dict[str, Any]] = []
        for n in range(index, patients, tenants):
            born = TODAY - timedelta(days=rng.randint(19 * 365, 88 * 365))
            condition = rng.randrange(len(CONDITIONS))
            first, last = rng.choice(FIRST), rng.choice(LAST)
            records.append({
                "synthetic": True, "tenant": name, "mrn": f"SYN{seed:02d}{n:05d}",
                "name": f"{first} {last}", "date_of_birth": born.isoformat(),
                "ssn": f"9{rng.randint(0, 99):02d}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
                "phone": f"702-555-01{rng.randint(0, 99):02d}",
                "email": f"{first}.{last}@patients.example".lower(),
                "address": f"{rng.randint(1, 999)} Example {rng.choice(['St', 'Ave', 'Way'])}, Sampletown, NV 89000",
                "insurance": {"plan": rng.choice(PLANS), "member_id": f"SYNM{rng.randint(100000, 999999)}"},
                "conditions": [CONDITIONS[condition]], "medications": [MEDICATIONS[condition]],
                "notes": [{"date": (TODAY - timedelta(days=rng.randint(1, 400))).isoformat(),
                           "text": f"Follow-up for {CONDITIONS[condition]}. Continues {MEDICATIONS[condition]}. No new concerns."}],
            })
        mark = canary(name, seed)
        if records:
            records[0]["notes"].append({"date": TODAY.isoformat(), "text": f"Test marker for tenant {name}: {mark}"})
        out["tenants"].append({"tenant": name, "canary": mark, "patients": records})
    return out


def to_csv(data: Dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["synthetic", "tenant", "mrn", "name", "date_of_birth", "ssn", "phone", "email", "address", "insurance_plan",
                     "member_id", "conditions", "medications", "latest_note"])
    for tenant in data["tenants"]:
        for p in tenant["patients"]:
            writer.writerow(["true", p["tenant"], p["mrn"], p["name"], p["date_of_birth"], p["ssn"], p["phone"], p["email"], p["address"],
                             p["insurance"]["plan"], p["insurance"]["member_id"], "; ".join(p["conditions"]),
                             "; ".join(p["medications"]), p["notes"][-1]["text"]])
    return buffer.getvalue()


def to_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2) + "\n"


def looks_synthetic(record: Dict[str, Any]) -> bool:
    """True when a record carries every marker this module plants. Use it to refuse anything else in a pilot."""
    return (record.get("synthetic") is True and str(record.get("mrn", "")).startswith("SYN") and str(record.get("ssn", "")).startswith("9")
            and "-555-01" in str(record.get("phone", "")) and str(record.get("email", "")).endswith(".example")
            and str(record.get("name", "")).endswith("-Synth"))
