import pytest

from patient_zero import profile


def test_catalogue_loads_and_counts():
    prof = profile.load()
    assert len(prof.controls) == 43
    assert len(prof.families) == 8
    assert profile.validate(prof) == []


def test_levels_are_cumulative():
    prof = profile.load()
    assert len(prof.for_level("L0")) == 5
    assert len(prof.for_level("L1")) == 35
    assert len(prof.for_level("L2")) == 43
    assert {c.family for c in prof.for_level("L0")} == {"GATE"}
    l1 = {c.id for c in prof.for_level("L1")}
    assert "TEST-5" not in l1 and "AGENT-1" not in l1


def test_unknown_level_and_control():
    prof = profile.load()
    with pytest.raises(ValueError):
        prof.for_level("L9")
    with pytest.raises(KeyError):
        prof.get("NOPE-1")


def test_validate_catches_duplicates():
    prof = profile.load()
    broken = profile.Profile(prof.version, prof.status, False, prof.levels, prof.families, prof.controls + [prof.controls[0]])
    assert any("duplicate" in e for e in profile.validate(broken))
