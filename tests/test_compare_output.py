"""Testing the output from the compare core: entity vital information and the diff report."""

from unittest.mock import Mock
import pytest
from reccmp.compare import Compare
from reccmp.compare.db import EntityDb
from reccmp.compare.diff import (
    CombinedDiffOutput,
)
from reccmp.compare.report import (
    ReccmpStatusReport,
    ReccmpComparedEntity,
    deserialize_reccmp_report,
    serialize_reccmp_report,
)
from reccmp.types import EntityType, ImageId
from reccmp.cvdump import CvdumpAnalysis
from .raw_image import RawImage


# pylint: disable=protected-access
def get_db(compare: Compare) -> EntityDb:
    """This is here to confine the pylint disable command to one spot
    and because we need a way to set up entities for each test without
    mocking a specific data source."""
    return compare._db


def to_report(compare: Compare) -> ReccmpStatusReport:
    """Creates a ReccmpStatusReport using the current reccmp state,
    serializes to JSON text, then deserializes back to a new report object.
    The goal is to see the state of the data after serialization."""
    report = ReccmpStatusReport(filename=compare.target_id)
    for match in compare.compare_all():
        orig_addr = f"0x{match.orig_addr:x}"
        recomp_addr = f"0x{match.recomp_addr:x}"

        report.entities[orig_addr] = ReccmpComparedEntity(
            orig_addr=orig_addr,
            name=match.name,
            type=match.match_type,
            accuracy=match.effective_ratio,
            recomp_addr=recomp_addr,
            is_effective_match=match.is_effective_match,
            is_stub=match.is_stub,
            rdiff=match.result.diff,
        )

    json_text = serialize_reccmp_report(report, diff_included=True)
    return deserialize_reccmp_report(json_text)


def get_udiff(entity: ReccmpComparedEntity) -> CombinedDiffOutput | None:
    """This is here for mypy type coercion and to protect against
    changes to the ReccmpStatusReport structure."""
    return entity.udiff


def test_empty():
    """The report should contain no entities if there are none in the database."""
    orig_bin = RawImage.from_memory()
    recomp_bin = RawImage.from_memory()
    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    # Nothing there.
    report = to_report(compare)
    assert len(report.entities) == 0


def test_not_matched():
    """The report should contain no entities if none are matched."""
    orig_bin = RawImage.from_memory()
    recomp_bin = RawImage.from_memory()
    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.ORIG, 0, type=EntityType.FUNCTION, name="test", size=1)

    # There is an entity, but no match.
    report = to_report(compare)
    assert len(report.entities) == 0


def test_matched_not_reported():
    """The report should contain no entities if there are no matched entities for us to compare.
    For now the compared entity types are FUNCTION (+VTORDISP) and VTABLE."""
    orig_bin = RawImage.from_memory()
    recomp_bin = RawImage.from_memory()
    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.RECOMP, 0, type=EntityType.LABEL, name="test")
        batch.match(0, 0)

    report = to_report(compare)
    assert len(report.entities) == 0


def test_matched_entity_no_type():
    """We cannot compare a matched entity without a type. (How would we do it?)"""
    orig_bin = RawImage.from_memory()
    recomp_bin = RawImage.from_memory()
    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.RECOMP, 0, name="test", size=1)
        batch.match(0, 0)

    with pytest.raises(AssertionError):
        # TODO: We could skip the entity instead of blowing up. GH #252
        to_report(compare)


def test_matched_function_missing_name():
    """We will not compare a function entity without a name."""
    orig_bin = RawImage.from_memory()
    recomp_bin = RawImage.from_memory()
    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, size=1)
        batch.match(0, 0)

    with pytest.raises(AssertionError):
        # TODO: We could skip the entity instead of blowing up. GH #252
        to_report(compare)


def test_matched_function_missing_size():
    """We will not compare a function entity without a size."""
    orig_bin = RawImage.from_memory()
    recomp_bin = RawImage.from_memory()
    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, name="test")
        batch.match(0, 0)

    report = to_report(compare)
    assert len(report.entities) == 0


def test_compare_function():
    """Demonstrate the bare minimum required to produce a function diff report."""
    orig_bin = RawImage.from_memory(b"\x90")  # nop
    recomp_bin = RawImage.from_memory(b"\x90")

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        # NAME, SIZE, and TYPE required for successful comparison.
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, name="test", size=1)
        batch.match(0, 0)

    report = to_report(compare)
    assert len(report.entities) == 1

    e = report.entities["0x0"]
    assert e is not None
    assert e.accuracy == 1.0
    assert e.is_stub is False

    # The type round-trips through serialization as the EntityType enum.
    assert e.type == EntityType.FUNCTION

    # String representation of address. No padding.
    assert e.orig_addr == "0x0"
    assert e.recomp_addr == "0x0"

    # No diff generated for a match
    udiff = get_udiff(e)
    assert udiff is None


def test_compare_function_stub():
    """Diff report is now INCLUDED for stubs.
    The distinction is that stubs are excluded from the total accuracy calculation."""
    orig_bin = RawImage.from_memory(b"\x90")  # nop
    recomp_bin = RawImage.from_memory(b"\xc3")  # ret

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(
            ImageId.RECOMP, 0, type=EntityType.FUNCTION, stub=True, name="test", size=1
        )
        batch.match(0, 0)

    report = to_report(compare)
    assert len(report.entities) == 1

    e = report.entities["0x0"]
    assert e is not None
    assert e.accuracy == 0.0
    assert e.is_stub is True

    udiff = get_udiff(e)
    assert udiff == [
        (
            "@@ -0x0,1 +0x0,1 @@",
            [{"orig": [("0x0", "nop ")], "recomp": [("0x0", "ret ")]}],
        )
    ]


def test_compare_function_diff():
    """Comparing this function where nothing matches."""
    orig_bin = RawImage.from_memory(b"\x90")  # nop
    recomp_bin = RawImage.from_memory(b"\xc3")

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        # NAME, SIZE, and TYPE required for successful comparison.
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, name="test", size=1)
        batch.match(0, 0)

    report = to_report(compare)
    assert len(report.entities) == 1

    e = report.entities["0x0"]
    assert e is not None
    assert e.accuracy == 0.0
    assert e.is_effective_match is False

    udiff = get_udiff(e)
    assert udiff is not None
    assert udiff == [
        (
            "@@ -0x0,1 +0x0,1 @@",
            [{"orig": [("0x0", "nop ")], "recomp": [("0x0", "ret ")]}],
        )
    ]


def test_compare_function_effective_match():
    """The diff is included for functions with an effective match."""
    orig_bin = RawImage.from_memory(b"\x39\xc8\x74\x00\x90")
    recomp_bin = RawImage.from_memory(b"\x39\xc1\x74\x00\x90")

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, name="test", size=5)
        batch.match(0, 0)

    report = to_report(compare)
    assert len(report.entities) == 1

    e = report.entities["0x0"]
    assert e is not None
    assert e.accuracy == 1.0
    assert e.is_effective_match is True

    udiff = get_udiff(e)
    assert udiff is not None
    assert udiff == [
        (
            "@@ -0x0,3 +0x0,3 @@",
            [
                {
                    "orig": [("0x0", "cmp eax, ecx")],
                    "recomp": [("0x0", "cmp ecx, eax")],
                },
                {"both": [("0x2", "je 4", "0x2"), ("0x4", "nop ", "0x4")]},
            ],
        )
    ]


def test_compare_function_diff_context():
    """The diff for this function should include two diff groups
    because there are more than 10 matching lines between the diffs."""

    # Bytes for each instruction we will use
    inst0 = b"\x8d\x09"  # lea ecx, [ecx]
    inst1 = b"\x31\xc0"  # xor eax, eax
    nop = b"\x90"  # nop

    # Different instructions at the beginning and end, separated by 30 NOP instructions.
    orig_mem = inst0 + nop * 30 + inst1
    recomp_mem = inst1 + nop * 30 + inst0

    orig_bin = RawImage.from_memory(orig_mem)
    recomp_bin = RawImage.from_memory(recomp_mem)

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        # NAME, SIZE, and TYPE required for successful comparison.
        batch.set(
            ImageId.RECOMP, 0, type=EntityType.FUNCTION, name="test", size=len(orig_mem)
        )
        batch.match(0, 0)

    report = to_report(compare)
    assert len(report.entities) == 1

    e = report.entities["0x0"]
    assert e is not None
    assert e.accuracy != 1.0
    assert e.is_effective_match is False

    udiff = get_udiff(e)
    assert udiff is not None

    # There are exactly two diff groups.
    # (assumed default n=10 context lines for difflib.SequenceMatcher)
    assert len(udiff) == 2
    [group0, group1] = udiff

    # The first group begins with this diff:
    assert group0[1][0] == {
        "orig": [("0x0", "lea ecx, [ecx]")],
        "recomp": [("0x0", "xor eax, eax")],
    }

    # 10 lines of context follow (all the matching NOP instructions)
    assert len(group0[1][1]["both"]) == 10

    # Some matching instructions outside the context windows are omitted.
    # The second group begins with more matches
    assert len(group1[1][0]["both"]) == 10

    # The second group ends with this diff:
    assert group1[1][-1] == {
        "orig": [("0x20", "xor eax, eax")],
        "recomp": [("0x20", "lea ecx, [ecx]")],
    }


def test_compare_vtable_match():
    """Vtable contents always appear in the diff report."""
    orig_bin = RawImage.from_memory(b"\x90\x00\x00\x00\x00")
    recomp_bin = RawImage.from_memory(b"\x90\x00\x00\x00\x00")

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        # Create vtable and single function. Match to create in both address spaces.
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, name="hello", size=1)
        batch.set(ImageId.RECOMP, 1, type=EntityType.VTABLE, name="test", size=4)
        batch.match(0, 0)
        batch.match(1, 1)

    report = to_report(compare)
    assert len(report.entities) == 2

    e = report.entities["0x1"]
    assert e is not None
    assert e.accuracy == 1.0

    # The vtable type round-trips through serialization.
    assert e.type == EntityType.VTABLE

    udiff = get_udiff(e)
    assert udiff is not None
    assert udiff == [
        (
            "@@ -vtable0x00,1 +vtable0x00,1 @@",
            [{"both": [("vtable0x00", "(0x0 / 0x0)  :  hello", "vtable0x00")]}],
        )
    ]


def test_compare_vtable_diff():
    """Vtable contents always appear in the diff report."""

    # Create 3 functions.
    function_bytes = b"\xc3\x00\x00\x00"  # `ret` padded to 4 bytes
    functions = function_bytes + function_bytes + function_bytes

    # Create two vtables that differ in the first and last entry.
    vtable_addr0 = b"\x00\x00\x00\x00"
    vtable_addr4 = b"\x04\x00\x00\x00"
    vtable_addr8 = b"\x08\x00\x00\x00"
    orig_mem = functions + vtable_addr8 + (vtable_addr0 * 30) + vtable_addr4
    recomp_mem = functions + vtable_addr4 + (vtable_addr0 * 30) + vtable_addr8

    orig_bin = RawImage.from_memory(orig_mem)
    recomp_bin = RawImage.from_memory(recomp_mem)

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        # Create vtable and single function. Match to create in both address spaces.
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, name="func0", size=1)
        batch.set(ImageId.RECOMP, 4, type=EntityType.FUNCTION, name="func1", size=1)
        batch.set(ImageId.RECOMP, 8, type=EntityType.FUNCTION, name="func2", size=1)
        batch.set(
            ImageId.RECOMP,
            12,
            type=EntityType.VTABLE,
            name="hello",
            size=len(orig_mem) - len(functions),
        )
        batch.match(0, 0)
        batch.match(4, 4)
        batch.match(8, 8)
        batch.match(12, 12)

    report = to_report(compare)
    assert len(report.entities) == 4

    e = report.entities["0xc"]
    assert e is not None
    assert e.accuracy != 1.0

    udiff = get_udiff(e)
    assert udiff is not None
    assert len(udiff) == 1

    [diff_hunk, diff_groups] = udiff[0]
    assert diff_hunk == "@@ -vtable0x00,32 +vtable0x00,32 @@"
    assert diff_groups[0].keys() == {"orig", "recomp"}
    assert diff_groups[1].keys() == {"both"}
    assert len(diff_groups[1]["both"]) > 10
    assert diff_groups[2].keys() == {"orig", "recomp"}


def test_aggregate_workflow():
    """Example of serializing a report, deserializing it, then serializing again.
    `reccmp-aggregate` manages report-only entities not derived from the EntityDb."""
    orig_bin = RawImage.from_memory(b"\x90")  # nop
    recomp_bin = RawImage.from_memory(b"\x90")

    # Same example as test_compare_function.
    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, name="test", size=1)
        batch.match(0, 0)

    report = to_report(compare)
    assert len(report.entities) == 1
    entity = report.entities["0x0"]

    # The function matches, it has no diff data.
    assert entity.udiff is None
    assert entity.rdiff is None

    # We should be able to serialize with and without diff data.
    serialize_reccmp_report(report, diff_included=False)
    serialize_reccmp_report(report, diff_included=True)
