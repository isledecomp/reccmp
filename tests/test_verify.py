"""Tests for actionable entity verification diagnostics."""

import logging
import struct

import pytest

from reccmp.compare.db import EntityDb
from reccmp.compare.verify import check_vtables
from reccmp.types import EntityType, ImageId

from .raw_image import RawImage


def _non_null_table(size: int, *, address: int = 0x20) -> RawImage:
    data = bytearray(address + size + 0x20)
    for slot in range(size // 4):
        struct.pack_into("<L", data, address + slot * 4, 0x1000 + slot * 4)
    return RawImage.from_memory(bytes(data))


def _add_vtable(
    db: EntityDb,
    *,
    orig_size: int | None = None,
    orig_max: int | None = None,
    recomp_size: int = 60,
) -> None:
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            0x20,
            type=EntityType.VTABLE,
            name="TCivUnit::`vftable'",
            size=orig_size,
            max_size=orig_max,
        )
        batch.set(
            ImageId.RECOMP,
            0x80,
            type=EntityType.VTABLE,
            name="TCivUnit::`vftable'",
            size=recomp_size,
        )
        batch.match(0x20, 0x80)


def test_vtable_boundary_warning_includes_interior_entity(
    caplog: pytest.LogCaptureFixture,
):
    db = EntityDb()
    _add_vtable(db, orig_max=32)
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            0x40,
            type=EntityType.DATA,
            name="g_interior_annotation",
        )

    caplog.set_level(logging.WARNING, logger="reccmp.compare.verify")
    check_vtables(db, _non_null_table(60))

    message = caplog.messages[-1]
    assert "addresses orig=0x00000020 recomp=0x00000080" in message
    assert "slots candidate=15 orig_bound=8 first_null=None trigger=boundary" in message
    assert (
        "bytes orig_size=None orig_max=32 recomp_size=60 recomp_max=None any=60"
        in message
    )
    assert "boundary 0x00000040 g_interior_annotation (data)" in message


def test_vtable_null_warning_reports_first_null_slot(
    caplog: pytest.LogCaptureFixture,
):
    db = EntityDb()
    _add_vtable(db, recomp_size=32)
    orig_bin = _non_null_table(32)
    data = bytearray(orig_bin.data)
    struct.pack_into("<L", data, 0x20 + 4 * 4, 0)

    caplog.set_level(logging.WARNING, logger="reccmp.compare.verify")
    check_vtables(db, RawImage.from_memory(bytes(data)))

    assert (
        "slots candidate=8 orig_bound=None first_null=4 trigger=null"
        in caplog.messages[-1]
    )


def test_vtable_declared_size_warning_is_explicit(
    caplog: pytest.LogCaptureFixture,
):
    db = EntityDb()
    _add_vtable(db, orig_size=12, recomp_size=16)

    caplog.set_level(logging.WARNING, logger="reccmp.compare.verify")
    check_vtables(db, _non_null_table(16))

    assert (
        "slots candidate=4 orig_bound=3 first_null=None trigger=declared_size"
        in caplog.messages[-1]
    )


def test_vtable_with_sufficient_non_null_extent_does_not_warn(
    caplog: pytest.LogCaptureFixture,
):
    db = EntityDb()
    _add_vtable(db, orig_max=32, recomp_size=16)

    caplog.set_level(logging.WARNING, logger="reccmp.compare.verify")
    check_vtables(db, _non_null_table(16))

    assert caplog.messages == []


def test_vtable_warning_honors_name_filter(caplog: pytest.LogCaptureFixture):
    db = EntityDb()
    _add_vtable(db, orig_max=32)

    caplog.set_level(logging.WARNING, logger="reccmp.compare.verify")
    check_vtables(db, _non_null_table(60), "tviewmgr")

    assert caplog.messages == []
