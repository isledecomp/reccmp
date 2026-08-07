"""Tests for relational VC5 SEH metadata pairing."""

import pytest

from reccmp.analysis.funcinfo import UnwindMapEntry
from reccmp.compare.db import EntityDb
from reccmp.compare.match_msvc import match_seh
from reccmp.types import EntityType, ImageId


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def add_seh_side(
    db: EntityDb,
    image_id: ImageId,
    owner: int,
    handler: int,
    funcinfo: int,
    *,
    unwinds: tuple[UnwindMapEntry, ...] = (),
):
    side = "orig" if image_id == ImageId.ORIG else "recomp"
    with db.batch() as batch:
        batch.set(
            image_id,
            handler,
            type=EntityType.LABEL,
            name="__ehhandler",
            **{
                f"seh_owner_{side}": owner,
                f"seh_funcinfo_{side}": funcinfo,
            },
        )
        if image_id == ImageId.ORIG:
            batch.set(
                image_id,
                funcinfo,
                type=EntityType.DATA,
                name="__ehfuncinfo",
                seh_unwinds_orig=unwinds,
            )
        else:
            batch.set(
                image_id,
                funcinfo,
                type=EntityType.DATA,
                name="__ehfuncinfo",
                seh_unwinds_recomp=unwinds,
            )
        for unwind in unwinds:
            if unwind.action_addr:
                batch.set(image_id, unwind.action_addr, type=EntityType.LABEL)


def test_match_seh_through_owner_and_unique_unwind_state(db):
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 500, type=EntityType.FUNCTION)
        batch.match(100, 500)
    add_seh_side(db, ImageId.ORIG, 100, 110, 120, unwinds=(UnwindMapEntry(-1, 130),))
    add_seh_side(db, ImageId.RECOMP, 500, 510, 520, unwinds=(UnwindMapEntry(-1, 530),))

    match_seh(db)

    assert db.is_match(110, 510)
    assert db.is_match(120, 520)
    assert db.is_match(130, 530)


def test_match_seh_skips_missing_or_ambiguous_owner_relationship(db):
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 500, type=EntityType.FUNCTION)
        batch.match(100, 500)
    add_seh_side(db, ImageId.ORIG, 100, 110, 120)
    add_seh_side(db, ImageId.ORIG, 100, 111, 121)
    add_seh_side(db, ImageId.RECOMP, 500, 510, 520)

    match_seh(db)

    assert db.get(ImageId.ORIG, 110).recomp_addr is None
    assert db.get(ImageId.ORIG, 111).recomp_addr is None
    assert db.get(ImageId.RECOMP, 510).orig_addr is None


def test_match_seh_has_no_generic_name_order_fallback(db):
    with db.batch() as batch:
        for addr in (110, 120):
            batch.set(ImageId.ORIG, addr, type=EntityType.DATA, name="__ehfuncinfo")
        for addr in (510, 520):
            batch.set(ImageId.RECOMP, addr, type=EntityType.DATA, name="__ehfuncinfo")

    match_seh(db)

    assert all(db.get(ImageId.ORIG, addr).recomp_addr is None for addr in (110, 120))


def test_match_seh_skips_non_unique_unwind_target_state(db):
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 500, type=EntityType.FUNCTION)
        batch.match(100, 500)
    add_seh_side(
        db,
        ImageId.ORIG,
        100,
        110,
        120,
        unwinds=(UnwindMapEntry(-1, 130), UnwindMapEntry(-1, 131)),
    )
    add_seh_side(db, ImageId.RECOMP, 500, 510, 520, unwinds=(UnwindMapEntry(-1, 530),))

    match_seh(db)

    assert db.get(ImageId.ORIG, 130).recomp_addr is None
    assert db.get(ImageId.ORIG, 131).recomp_addr is None
