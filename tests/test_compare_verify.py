"""Tests for the entity problem checks in compare/verify.py (check_vtables)."""

import struct
from unittest.mock import Mock
import pytest
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb
from reccmp.compare.verify import check_vtables


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def orig_bin_with_table(table: bytes) -> Mock:
    """Stub binary whose read() serves a window into the given orig vtable bytes."""
    orig_bin = Mock()
    orig_bin.read = lambda addr, size: table[:size]
    return orig_bin


def set_vtable_match(
    db: EntityDb,
    orig_size: int | None = None,
    recomp_size: int | None = None,
    orig_max_size: int | None = None,
):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            100,
            name="Pet::`vftable'",
            type=EntityType.VTABLE,
            size=orig_size,
            max_size=orig_max_size,
        )
        batch.set(
            ImageId.RECOMP,
            500,
            name="Pet::`vftable'",
            type=EntityType.VTABLE,
            size=recomp_size,
        )
        batch.match(100, 500)


def test_known_orig_size_overrules_recomp_estimate(db, caplog):
    """The recomp size is an estimate (next-symbol distance or section
    contribution) that may include trailing alignment padding. A known orig
    size must take priority so the padding bytes after the true table are
    never scanned for null pointers."""
    set_vtable_match(db, orig_size=8, recomp_size=16)
    # Two real entries, then null alignment padding after the table.
    table = struct.pack("<4L", 0x1000, 0x2000, 0, 0)

    with caplog.at_level("WARNING"):
        check_vtables(db, orig_bin_with_table(table))

    assert "is larger than orig vtable" not in caplog.text


def test_known_orig_size_conflicts_with_upper_bound(db, caplog):
    """A supplied orig size that exceeds the next-entity upper bound is
    still reported."""
    set_vtable_match(db, orig_size=12, recomp_size=12, orig_max_size=8)
    table = struct.pack("<3L", 0x1000, 0x2000, 0x3000)

    with caplog.at_level("WARNING"):
        check_vtables(db, orig_bin_with_table(table))

    assert "is larger than orig vtable" in caplog.text


def test_unknown_orig_size_max_size_heuristic(db, caplog):
    """Without an orig size, the next-entity upper bound heuristic still
    applies to the recomp size."""
    set_vtable_match(db, recomp_size=12, orig_max_size=8)
    table = struct.pack("<3L", 0x1000, 0x2000, 0x3000)

    with caplog.at_level("WARNING"):
        check_vtables(db, orig_bin_with_table(table))

    assert "is larger than orig vtable" in caplog.text


def test_unknown_orig_size_null_scan_heuristic(db, caplog):
    """Without an orig size, a null pointer inside the recomp-sized window
    still marks the recomp vtable as larger."""
    set_vtable_match(db, recomp_size=16)
    table = struct.pack("<4L", 0x1000, 0x2000, 0, 0)

    with caplog.at_level("WARNING"):
        check_vtables(db, orig_bin_with_table(table))

    assert "is larger than orig vtable" in caplog.text


def test_unknown_orig_size_clean_table_no_warning(db, caplog):
    """Without an orig size, a table with no nulls inside the window and a
    roomy upper bound is not reported."""
    set_vtable_match(db, recomp_size=12, orig_max_size=16)
    table = struct.pack("<3L", 0x1000, 0x2000, 0x3000)

    with caplog.at_level("WARNING"):
        check_vtables(db, orig_bin_with_table(table))

    assert "is larger than orig vtable" not in caplog.text
