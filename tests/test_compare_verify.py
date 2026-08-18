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


def stub_image(table: bytes) -> Mock:
    """Stub binary whose read() serves a window into the given vtable bytes."""
    image = Mock()
    image.read = lambda addr, size: table[addr : addr + size]
    return image


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


def test_known_orig_size_ignores_recomp_padding(db, caplog):
    """The recomp size may over-count the table by a trailing alignment slot.
    That slot is not a virtual function, so it must not be reported as one."""
    set_vtable_match(db, orig_size=8, recomp_size=12)
    # Two real entries, then the alignment slot. Both tables are identical.
    table = struct.pack("<3L", 0x1000, 0x2000, 0)

    with caplog.at_level("WARNING"):
        check_vtables(db, stub_image(table), stub_image(table))

    assert "is larger than orig vtable" not in caplog.text


def test_known_orig_size_reports_real_extra_entry(db, caplog):
    """A non-null pointer past the end of the orig table is a virtual function
    that orig does not have, and is still reported."""
    set_vtable_match(db, orig_size=8, recomp_size=12)
    orig_table = struct.pack("<3L", 0x1000, 0x2000, 0)
    recomp_table = struct.pack("<3L", 0x1000, 0x2000, 0x3000)

    with caplog.at_level("WARNING"):
        check_vtables(db, stub_image(orig_table), stub_image(recomp_table))

    assert "is larger than orig vtable" in caplog.text


def test_known_orig_size_equal_sizes_no_warning(db, caplog):
    """Nothing to report when the two sizes agree."""
    set_vtable_match(db, orig_size=8, recomp_size=8)
    table = struct.pack("<2L", 0x1000, 0x2000)

    with caplog.at_level("WARNING"):
        check_vtables(db, stub_image(table), stub_image(table))

    assert not caplog.text


def test_known_orig_size_conflicts_with_upper_bound(db, caplog):
    """A supplied orig size that exceeds the next-entity upper bound cannot be
    correct. That is a problem with the data source, not a size difference, so
    it is reported as its own thing."""
    set_vtable_match(db, orig_size=12, recomp_size=12, orig_max_size=8)
    table = struct.pack("<3L", 0x1000, 0x2000, 0x3000)

    with caplog.at_level("WARNING"):
        check_vtables(db, stub_image(table), stub_image(table))

    assert "overruns the next entity" in caplog.text
    assert "is larger than orig vtable" not in caplog.text


def test_unknown_orig_size_max_size_heuristic(db, caplog):
    """Without an orig size, the next-entity upper bound heuristic still
    applies to the recomp size."""
    set_vtable_match(db, recomp_size=12, orig_max_size=8)
    table = struct.pack("<3L", 0x1000, 0x2000, 0x3000)

    with caplog.at_level("WARNING"):
        check_vtables(db, stub_image(table), stub_image(table))

    assert "is larger than orig vtable" in caplog.text


def test_unknown_orig_size_null_scan_heuristic(db, caplog):
    """Without an orig size, a null pointer inside the recomp-sized window
    still marks the recomp vtable as larger."""
    set_vtable_match(db, recomp_size=16)
    table = struct.pack("<4L", 0x1000, 0x2000, 0, 0)

    with caplog.at_level("WARNING"):
        check_vtables(db, stub_image(table), stub_image(table))

    assert "is larger than orig vtable" in caplog.text


def test_unknown_orig_size_clean_table_no_warning(db, caplog):
    """Without an orig size, a table with no nulls inside the window and a
    roomy upper bound is not reported."""
    set_vtable_match(db, recomp_size=12, orig_max_size=16)
    table = struct.pack("<3L", 0x1000, 0x2000, 0x3000)

    with caplog.at_level("WARNING"):
        check_vtables(db, stub_image(table), stub_image(table))

    assert "is larger than orig vtable" not in caplog.text
