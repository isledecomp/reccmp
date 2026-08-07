"""Recomputed compiler-alias equivalence for folded vtable targets.

MSVC folds identical COMDAT bodies (template deleting destructors above
all), so one original address may serve vtable slots whose rebuilt targets
are distinct functions. A repeated original target may match a distinct
rebuilt target only when the two bodies are provably the same compiled
code with every relocated operand resolving to a named, paired entity;
non-equivalent targets and unproven operands still fail.
"""

from unittest.mock import Mock
import pytest
from reccmp.cvdump.types import CvdumpTypesParser
from reccmp.compare.core import Compare
from reccmp.compare.db import EntityDb, ReccmpEntity
from reccmp.compare.event import ReccmpReportProtocol
from reccmp.compare.functions import FunctionComparator
from reccmp.compare.lines import LinesDb
from reccmp.types import EntityType, ImageId

ORIG_BODY = 0x200
RECOMP_BODY = 0x400
ORIG_CALLEE = 0x300
RECOMP_CALLEE = 0x500


def _call_rel32(source: int, destination: int) -> bytes:
    return b"\xe8" + (destination - (source + 5)).to_bytes(4, "little", signed=True)


def _body(start: int, callee: int, tail: bytes = b"\x5e\xc3") -> bytes:
    # push esi; call callee; pop esi; ret
    return b"\x56" + _call_rel32(start + 1, callee) + tail


def _image(body: bytes) -> Mock:
    image = Mock(spec=[])
    image.read = Mock(return_value=body)
    image.imagebase = 0
    image.is_relocated_addr = Mock(return_value=False)
    image.is_debug = Mock(return_value=False)
    return image


def _comparator(
    db: EntityDb, orig_body: bytes, recomp_body: bytes
) -> FunctionComparator:
    lines_db = LinesDb()
    report = Mock(spec=ReccmpReportProtocol)
    return FunctionComparator(
        db,
        lines_db,
        _image(orig_body),
        _image(recomp_body),
        report,
        CvdumpTypesParser(),
    )


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def _annotate_callee(db: EntityDb) -> None:
    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            RECOMP_CALLEE,
            name="operator_delete",
            type=EntityType.FUNCTION,
        )
        batch.match(ORIG_CALLEE, RECOMP_CALLEE)


def test_identical_bodies_with_paired_operands_are_alias_equivalent(
    db: EntityDb,
) -> None:
    _annotate_callee(db)
    orig = _body(ORIG_BODY, ORIG_CALLEE)
    recomp = _body(RECOMP_BODY, RECOMP_CALLEE)
    comparator = _comparator(db, orig, recomp)

    assert comparator.raw_pair_alias_equivalent(ORIG_BODY, RECOMP_BODY, len(orig))


def test_different_instructions_are_not_alias_equivalent(db: EntityDb) -> None:
    _annotate_callee(db)
    orig = _body(ORIG_BODY, ORIG_CALLEE, tail=b"\x5f\xc3")  # pop edi
    recomp = _body(RECOMP_BODY, RECOMP_CALLEE)
    comparator = _comparator(db, orig, recomp)

    assert not comparator.raw_pair_alias_equivalent(ORIG_BODY, RECOMP_BODY, len(orig))


def test_unresolved_operands_are_not_evidence(db: EntityDb) -> None:
    # Same shape, but the call target is annotated on neither side: both
    # sanitize to a positional placeholder, which must not count as proof.
    orig = _body(ORIG_BODY, ORIG_CALLEE)
    recomp = _body(RECOMP_BODY, RECOMP_CALLEE)
    comparator = _comparator(db, orig, recomp)

    assert not comparator.raw_pair_alias_equivalent(ORIG_BODY, RECOMP_BODY, len(orig))


def test_truncated_read_is_not_alias_equivalent(db: EntityDb) -> None:
    _annotate_callee(db)
    orig = _body(ORIG_BODY, ORIG_CALLEE)
    recomp = _body(RECOMP_BODY, RECOMP_CALLEE)
    comparator = _comparator(db, orig, recomp[:-1])  # short read from recomp

    assert not comparator.raw_pair_alias_equivalent(ORIG_BODY, RECOMP_BODY, len(orig))


def test_vtable_slot_accepts_only_proven_alias_targets(db: EntityDb) -> None:
    # pylint: disable=protected-access
    _annotate_callee(db)
    orig = _body(ORIG_BODY, ORIG_CALLEE)
    recomp = _body(RECOMP_BODY, RECOMP_CALLEE)
    fake_compare = Mock(spec=[])
    fake_compare.function_comparator = _comparator(db, orig, recomp)

    slot_entity = ReccmpEntity(
        None,
        RECOMP_BODY,
        {"type": EntityType.FUNCTION, "recomp_size": len(recomp), "name": "T::sdd"},
    )
    assert Compare._slot_alias_equivalent(fake_compare, ORIG_BODY, slot_entity)

    sized_zero = ReccmpEntity(
        None, RECOMP_BODY, {"type": EntityType.FUNCTION, "name": "T::sdd"}
    )
    assert not Compare._slot_alias_equivalent(fake_compare, ORIG_BODY, sized_zero)
    assert not Compare._slot_alias_equivalent(fake_compare, ORIG_BODY, None)
