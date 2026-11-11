"""Load and validate the control catalogue."""
from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from typing import Dict, List, Optional

import yaml

LEVELS = ("L0", "L1", "L2")


@dataclass(frozen=True)
class Control:
    id: str
    family: str
    min_level: str
    keyword: str
    statement: str


@dataclass(frozen=True)
class Profile:
    version: str
    status: str
    mappings_verified: bool
    levels: Dict[str, dict]
    families: Dict[str, dict]
    controls: List[Control]

    def get(self, control_id: str) -> Control:
        for c in self.controls:
            if c.id == control_id:
                return c
        raise KeyError(f"unknown control: {control_id}")

    def for_level(self, level: str) -> List[Control]:
        """Controls required at a level. Levels are cumulative."""
        if level not in LEVELS:
            raise ValueError(f"unknown level: {level} (expected one of {LEVELS})")
        rank = LEVELS.index(level)
        return [c for c in self.controls if LEVELS.index(c.min_level) <= rank]

    def for_family(self, family: str) -> List[Control]:
        return [c for c in self.controls if c.family == family]


def load(path: Optional[str] = None) -> Profile:
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    else:
        text = resources.files("patient_zero").joinpath("data/controls.yaml").read_text("utf-8")
        raw = yaml.safe_load(text)
    profile = Profile(
        version=str(raw["version"]),
        status=str(raw.get("status", "draft")),
        mappings_verified=bool(raw.get("mappings_verified", False)),
        levels=raw["levels"],
        families=raw["families"],
        controls=[Control(**c) for c in raw["controls"]],
    )
    errors = validate(profile)
    if errors:
        raise ValueError("invalid profile: " + "; ".join(errors))
    return profile


def validate(profile: Profile) -> List[str]:
    errors: List[str] = []
    seen = set()
    for c in profile.controls:
        if c.id in seen:
            errors.append(f"duplicate id {c.id}")
        seen.add(c.id)
        if c.family not in profile.families:
            errors.append(f"{c.id}: unknown family {c.family}")
        if c.min_level not in LEVELS:
            errors.append(f"{c.id}: unknown level {c.min_level}")
        if c.keyword not in ("shall", "should"):
            errors.append(f"{c.id}: keyword must be shall or should")
        if c.keyword not in c.statement:
            errors.append(f"{c.id}: statement does not contain '{c.keyword}'")
    for name in profile.families:
        if not any(c.family == name for c in profile.controls):
            errors.append(f"family {name} has no controls")
    for level in LEVELS:
        if level not in profile.levels:
            errors.append(f"level {level} is not described")
    return errors
