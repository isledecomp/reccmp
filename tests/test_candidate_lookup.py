"""Tests for the cross-side operand equivalence candidates.
An address is described by the set of (matched entity, delta) pairs that
could plausibly refer to it. Two operands (one per image) are equivalent
if they share an interpretation. See create_candidate_lookup."""

import pytest
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb
from reccmp.compare.asm.replacement import create_candidate_lookup


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def test_matched_entities_only(db: EntityDb):
    """Only matched entities can anchor a candidate: the interpretation
    must exist in both images to be comparable."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, name="Test", type=EntityType.DATA, size=10)
        batch.set(ImageId.ORIG, 200, name="Hello", type=EntityType.DATA, size=10)
        batch.set(ImageId.RECOMP, 1200, name="Hello", type=EntityType.DATA, size=10)
        batch.match(200, 1200)

    lookup = create_candidate_lookup(db, ImageId.ORIG)

    # No candidates for the unmatched entity.
    assert not lookup(104)

    # The matched entity anchors interior references on both sides.
    assert (200, 4) in lookup(204)
    assert (200, 4) in create_candidate_lookup(db, ImageId.RECOMP)(1204)


def test_candidate_windows(db: EntityDb):
    """Candidates cover the entity range widened by a small tolerance:
    a bit before the start and a bit past the end."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 1000, name="Hello", type=EntityType.DATA, size=100)
        batch.set(ImageId.RECOMP, 5000, name="Hello", type=EntityType.DATA, size=100)
        batch.match(1000, 5000)

    lookup = create_candidate_lookup(db, ImageId.ORIG)

    # Interior and exact.
    assert (1000, 0) in lookup(1000)
    assert (1000, 50) in lookup(1050)
    assert (1000, 99) in lookup(1099)

    # One-past-the-end and slightly beyond (e.g. the end bound of an
    # array of structs, offset by a struct member).
    assert (1000, 100) in lookup(1100)
    assert (1000, 104) in lookup(1104)
    assert (1000, 105) not in lookup(1105)

    # Slightly before the entity (e.g. an array base biased by the
    # first index).
    assert (1000, -4) in lookup(996)
    assert (1000, -16) in lookup(984)
    assert (1000, -17) not in lookup(983)


def test_collision_produces_both_candidates(db: EntityDb):
    """One-past-the-end of one entity can coincide with the start of the
    next. Both interpretations must be produced: the other image decides
    which one (if any) is shared."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 1000, name="table", type=EntityType.DATA, size=100)
        batch.set(ImageId.RECOMP, 5000, name="table", type=EntityType.DATA, size=100)
        batch.match(1000, 5000)
        # Directly follows the table in orig only.
        batch.set(ImageId.ORIG, 1100, name="next", type=EntityType.DATA, size=4)
        batch.set(ImageId.RECOMP, 7000, name="next", type=EntityType.DATA, size=4)
        batch.match(1100, 7000)

    orig_lookup = create_candidate_lookup(db, ImageId.ORIG)
    recomp_lookup = create_candidate_lookup(db, ImageId.RECOMP)

    assert {(1000, 100), (1100, 0)} <= orig_lookup(1100)

    # The recomp layout separates the entities, so only the table
    # interpretation appears... and the intersection decides.
    assert (1000, 100) in recomp_lookup(5100)
    assert orig_lookup(1100) & recomp_lookup(5100) == {(1000, 100)}
    # ...while the recomp address of "next" only matches the exact
    # interpretation.
    assert orig_lookup(1100) & recomp_lookup(7000) == {(1100, 0)}


def test_small_entity_one_past_end(db: EntityDb):
    """One-past-the-end candidates apply to entities of any size.
    (Unlike name replacement, which requires an array-sized entity:
    a candidate by itself proves nothing until the other side shares it.)"""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 1000, name="Hello", type=EntityType.DATA, size=4)
        batch.set(ImageId.RECOMP, 5000, name="Hello", type=EntityType.DATA, size=4)
        batch.match(1000, 5000)

    lookup = create_candidate_lookup(db, ImageId.ORIG)
    assert (1000, 4) in lookup(1004)


def test_function_interior(db: EntityDb):
    """A function can anchor references into its own body (e.g. its jump
    tables)."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0x1000, name="fn", type=EntityType.FUNCTION)
        batch.set(
            ImageId.RECOMP, 0x5000, name="fn", type=EntityType.FUNCTION, size=0x500
        )
        batch.match(0x1000, 0x5000)

    # n.b. Function entities usually have no orig size; the recomp size
    # is used as a stand-in.
    lookup = create_candidate_lookup(db, ImageId.ORIG)
    assert (0x1000, 0x123) in lookup(0x1123)

    # Code entities are units: unlike variables, a reference just before
    # or just past a function does not relate to it.
    assert not lookup(0x1000 - 4)
    assert not lookup(0x1000 + 0x500)


def test_excluded_types(db: EntityDb):
    """Entities that do not occupy bytes of their own cannot anchor
    a reference."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 1000, name="line", type=EntityType.LINE)
        batch.set(ImageId.RECOMP, 5000, name="line", type=EntityType.LINE)
        batch.match(1000, 5000)
        batch.set(ImageId.ORIG, 2000, name="import", type=EntityType.IMPORT, size=4)
        batch.set(ImageId.RECOMP, 6000, name="import", type=EntityType.IMPORT, size=4)
        batch.match(2000, 6000)

    lookup = create_candidate_lookup(db, ImageId.ORIG)
    assert not lookup(1002)
    assert not lookup(2002)


def test_string_interior(db: EntityDb):
    """Strings occupy bytes and can anchor nearby references, e.g. when
    an unannotated variable follows a string in both images."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 1000, name='"str"', type=EntityType.STRING, size=6)
        batch.set(ImageId.RECOMP, 5000, name='"str"', type=EntityType.STRING, size=6)
        batch.match(1000, 5000)

    lookup = create_candidate_lookup(db, ImageId.ORIG)
    assert (1000, 4) in lookup(1004)
    assert (1000, -16) in lookup(984)
