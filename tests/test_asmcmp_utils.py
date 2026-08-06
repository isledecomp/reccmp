from reccmp.utils import entity_diff_change, ReccmpDiffJudgement
from reccmp.compare.report import ReccmpComparedEntity


def entity(
    *, accuracy: float, is_stub: bool = False, is_effective_match: bool = False
) -> ReccmpComparedEntity:
    """Helper to create entities with dummy values for required fields: address, name.
    The only relevant fields are: accuracy, is_stub, is_effective_match"""
    return ReccmpComparedEntity(
        orig_addr=0x400000,
        name="Test",
        accuracy=accuracy,
        is_stub=is_stub,
        is_effective_match=is_effective_match,
    )


def test_diff_new_entity():
    """If the entity did not exist in the saved report, it is flagged as NEW regardless of status."""
    for new in [
        entity(accuracy=1.0),
        entity(accuracy=0.0),
        entity(accuracy=0.5, is_stub=True),
        entity(accuracy=0.5, is_effective_match=True),
        entity(accuracy=0.5, is_stub=True, is_effective_match=True),
    ]:
        assert entity_diff_change(None, new) == ReccmpDiffJudgement.NEW


def test_diff_dropped_entity():
    """If the entity did exist in the saved report, but it does not exist now,
    it is flagged as DROPPED regardless of status."""
    for saved in [
        entity(accuracy=1.0),
        entity(accuracy=0.0),
        entity(accuracy=0.5, is_stub=True),
        entity(accuracy=0.5, is_effective_match=True),
        entity(accuracy=0.5, is_stub=True, is_effective_match=True),
    ]:
        assert entity_diff_change(saved, None) == ReccmpDiffJudgement.DROPPED


def test_diff_no_change():
    """Do not report accuracy changes if nothing has changed."""
    ent = entity(accuracy=0.5)
    assert entity_diff_change(ent, ent) == ReccmpDiffJudgement.NO_CHANGE


def test_diff_stub_changes():
    """Do not report accuracy changes if the entity is a stub in both reports."""
    low_stub = entity(accuracy=0.5, is_stub=True)
    high_stub = entity(accuracy=0.8, is_stub=True)
    assert entity_diff_change(low_stub, high_stub) == ReccmpDiffJudgement.NO_CHANGE
    assert entity_diff_change(high_stub, low_stub) == ReccmpDiffJudgement.NO_CHANGE


def test_diff_stub_effective_changes():
    """Do not report effective-match changes if the entity is a stub in both reports."""
    low_stub = entity(accuracy=0.5, is_stub=True, is_effective_match=True)
    high_stub = entity(accuracy=1.0, is_stub=True)
    assert entity_diff_change(low_stub, high_stub) == ReccmpDiffJudgement.NO_CHANGE
    assert entity_diff_change(high_stub, low_stub) == ReccmpDiffJudgement.NO_CHANGE


def test_diff_stub_to_non_stub():
    """Any move from a stub to a non-stub is an INCREASE, regardless of score."""
    ent = entity(accuracy=0.6)

    low_stub = entity(accuracy=0.5, is_stub=True)
    high_stub = entity(accuracy=0.8, is_stub=True)
    assert entity_diff_change(low_stub, ent) == ReccmpDiffJudgement.INCREASE
    assert entity_diff_change(high_stub, ent) == ReccmpDiffJudgement.INCREASE
    assert entity_diff_change(ent, low_stub) == ReccmpDiffJudgement.DECREASE
    assert entity_diff_change(ent, high_stub) == ReccmpDiffJudgement.DECREASE

    low_stub_effective = entity(accuracy=0.5, is_stub=True, is_effective_match=True)
    high_stub_effective = entity(accuracy=0.8, is_stub=True, is_effective_match=True)
    assert entity_diff_change(low_stub_effective, ent) == ReccmpDiffJudgement.INCREASE
    assert entity_diff_change(high_stub_effective, ent) == ReccmpDiffJudgement.INCREASE
    assert entity_diff_change(ent, low_stub_effective) == ReccmpDiffJudgement.DECREASE
    assert entity_diff_change(ent, high_stub_effective) == ReccmpDiffJudgement.DECREASE


def test_diff_accuracy_change():
    """Report accuracy change for non-stub, non-effective."""
    low_ent = entity(accuracy=0.5)
    high_ent = entity(accuracy=0.8)
    assert entity_diff_change(low_ent, high_ent) == ReccmpDiffJudgement.INCREASE
    assert entity_diff_change(high_ent, low_ent) == ReccmpDiffJudgement.DECREASE


def test_diff_upgrade_to_effective():
    """Moving from any non-match to an effective match is an INCREASE."""
    low_ent = entity(accuracy=0.5)
    effective = entity(accuracy=0.8, is_effective_match=True)
    assert entity_diff_change(low_ent, effective) == ReccmpDiffJudgement.INCREASE

    # Report an improvement even though the raw score is lower for the effective match.
    lower_effective = entity(accuracy=0.2, is_effective_match=True)
    assert entity_diff_change(low_ent, lower_effective) == ReccmpDiffJudgement.INCREASE


def test_diff_downgrade_from_effective():
    """Moving from an effective match to any non-match is a DECREASE."""
    low_ent = entity(accuracy=0.5)
    effective = entity(accuracy=0.8, is_effective_match=True)
    assert entity_diff_change(effective, low_ent) == ReccmpDiffJudgement.DECREASE

    # Report a degradation even though the raw score is higher for the non-effective match.
    higher_ent = entity(accuracy=0.9)
    assert entity_diff_change(effective, higher_ent) == ReccmpDiffJudgement.DECREASE


def test_diff_effective_to_match():
    """Moving from an effective-match to an exact match is an INCREASE. See GH #431."""
    match = entity(accuracy=1.0)
    effective = entity(accuracy=0.8, is_effective_match=True)
    assert entity_diff_change(effective, match) == ReccmpDiffJudgement.INCREASE


def test_diff_match_to_effective():
    """Moving from an exact match to an effective match is judged to be ENTROPY."""
    match = entity(accuracy=1.0)
    effective = entity(accuracy=0.8, is_effective_match=True)
    assert entity_diff_change(match, effective) == ReccmpDiffJudgement.ENTROPY


def test_diff_effective_to_effective():
    """Do not report accuracy changes for effective matches."""
    low_effective = entity(accuracy=0.2, is_effective_match=True)
    high_effective = entity(accuracy=0.8, is_effective_match=True)
    assert (
        entity_diff_change(low_effective, high_effective)
        == ReccmpDiffJudgement.NO_CHANGE
    )
    assert (
        entity_diff_change(high_effective, low_effective)
        == ReccmpDiffJudgement.NO_CHANGE
    )
