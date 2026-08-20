"""Tests for the entity problem checks in compare/verify.py (check_vtables)."""

import pytest
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb
from reccmp.compare.verify import check_vtables


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def set_vtable_match(
    db: EntityDb,
    orig_size: int | None = None,
    recomp_size: int | None = None,
    orig_max_size: int | None = None,
):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            0,
            name="Pet::`vftable'",
            type=EntityType.VTABLE,
            size=orig_size,
            max_size=orig_max_size,
        )
        batch.set(
            ImageId.RECOMP,
            0,
            name="Pet::`vftable'",
            type=EntityType.VTABLE,
            size=recomp_size,
        )
        batch.match(0, 0)


def test_size_difference_not_warned(db, caplog):
    """A recomp vtable larger than orig is not reported here: the difference
    shows up in the regular vtable comparison. (Warning dropped on review.)"""
    set_vtable_match(db, orig_size=8, recomp_size=12)

    with caplog.at_level("WARNING"):
        check_vtables(db)

    assert not caplog.text


def test_known_orig_size_conflicts_with_upper_bound(db, caplog):
    """A supplied orig size that exceeds the next-entity upper bound cannot be
    correct. That is a problem with the data source, not a size difference, so
    it is reported as its own thing."""
    set_vtable_match(db, orig_size=12, recomp_size=12, orig_max_size=8)

    with caplog.at_level("WARNING"):
        check_vtables(db)

    assert "overruns the next entity" in caplog.text


def test_unknown_orig_size_no_warning(db, caplog):
    """Without an orig size there is nothing to validate."""
    set_vtable_match(db, recomp_size=16)

    with caplog.at_level("WARNING"):
        check_vtables(db)

    assert not caplog.text
