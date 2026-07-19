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
    report_function_alignment,
    report_function_accuracy,
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
    report = compare.to_report(filename=compare.target_id)
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

    # Skip the entity instead of blowing up. (GH #252)
    report = to_report(compare)
    assert not report.entities


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

    e = report.entities[0]
    assert e is not None
    assert e.accuracy == 1.0
    assert e.is_stub is False

    # The type round-trips through serialization as the EntityType enum.
    assert e.type == EntityType.FUNCTION
    assert e.orig_addr == 0
    assert e.recomp_addr == 0

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

    e = report.entities[0]
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

    e = report.entities[0]
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

    e = report.entities[0]
    assert e is not None
    # Should retain non-effective accuracy.
    assert e.accuracy != 1.0
    assert e.effective_accuracy == 1.0
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

    e = report.entities[0]
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
    orig_bin = RawImage.from_memory(b"\x00" * 0x1004 + b"\x00\x10\x00\x00")
    recomp_bin = RawImage.from_memory(b"\x00" * 0x1004 + b"\x00\x10\x00\x00")

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        # Create vtable and single function. Match to create in both address spaces.
        batch.set(
            ImageId.RECOMP, 0x1000, type=EntityType.FUNCTION, name="hello", size=1
        )
        batch.set(ImageId.RECOMP, 0x1004, type=EntityType.VTABLE, name="test", size=4)
        batch.match(0x1000, 0x1000)
        batch.match(0x1004, 0x1004)

    report = to_report(compare)
    assert len(report.entities) == 2

    e = report.entities[0x1004]
    assert e is not None
    assert e.accuracy == 1.0

    # The vtable type round-trips through serialization.
    assert e.type == EntityType.VTABLE

    udiff = get_udiff(e)
    assert udiff is not None
    assert udiff == [
        (
            "@@ -vtable0x00,1 +vtable0x00,1 @@",
            [{"both": [("vtable0x00", "(0x1000 / 0x1000)  :  hello", "vtable0x00")]}],
        )
    ]


def test_compare_vtable_diff():
    """Vtable contents always appear in the diff report."""

    # Create 3 functions.
    function_bytes = b"\xc3\x00\x00\x00"  # `ret` padded to 4 bytes
    functions = function_bytes + function_bytes + function_bytes

    # Create two vtables that differ in the first and last entry.
    vtable_addr1000 = b"\x00\x10\x00\x00"
    vtable_addr1004 = b"\x04\x10\x00\x00"
    vtable_addr1008 = b"\x08\x10\x00\x00"
    orig_mem = (
        b"\x00" * 0x1000
        + functions
        + vtable_addr1008
        + (vtable_addr1000 * 30)
        + vtable_addr1004
    )
    recomp_mem = (
        b"\x00" * 0x1000
        + functions
        + vtable_addr1004
        + (vtable_addr1000 * 30)
        + vtable_addr1008
    )

    orig_bin = RawImage.from_memory(orig_mem)
    recomp_bin = RawImage.from_memory(recomp_mem)

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        # Create vtable and single function. Match to create in both address spaces.
        batch.set(
            ImageId.RECOMP, 0x1000, type=EntityType.FUNCTION, name="func0", size=1
        )
        batch.set(
            ImageId.RECOMP, 0x1004, type=EntityType.FUNCTION, name="func1", size=1
        )
        batch.set(
            ImageId.RECOMP, 0x1008, type=EntityType.FUNCTION, name="func2", size=1
        )
        batch.set(
            ImageId.RECOMP,
            0x100C,
            type=EntityType.VTABLE,
            name="hello",
            size=len(orig_mem) - len(functions) - 0x1000,
        )
        batch.match(0x1000, 0x1000)
        batch.match(0x1004, 0x1004)
        batch.match(0x1008, 0x1008)
        batch.match(0x100C, 0x100C)

    report = to_report(compare)
    assert len(report.entities) == 4

    e = report.entities[0x100C]
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


def test_compare_vtable_thunk_resolution():
    """A vtable slot that points at an incremental-link jmp thunk should compare
    equal to a slot that points directly at the thunk's target function."""

    # orig: function@0, thunk@4 (jmp to function), vtable@8 -> slot points to thunk.
    orig_mem = (
        b"\xc3\x00\x00\x00"  # function@0
        + b"\xe9\xf7\xff\xff\xff"  # thunk@4: jmp -9 (-> 0), int3-padded below
        + b"\xcc\xcc\xcc"
        + b"\x04\x00\x00\x00"  # vtable@12: slot -> thunk@4
    )
    # recomp: function@0, vtable@4 -> slot points directly to function.
    recomp_mem = b"\xc3\x00\x00\x00" + b"\x00\x00\x00\x00"

    orig_bin = RawImage.from_memory(orig_mem)
    recomp_bin = RawImage.from_memory(recomp_mem)

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, name="func", size=1)
        # The thunk only exists in the original; it refs the real function.
        batch.set(ImageId.ORIG, 4, type=EntityType.THUNK, name="func_thunk", ref=0)
        batch.set(ImageId.RECOMP, 4, type=EntityType.VTABLE, name="hello", size=4)
        batch.match(0, 0)
        batch.match(12, 4)

    report = to_report(compare)

    e = report.entities["0xc"]
    assert e is not None
    # Without thunk resolution the slot would mismatch (thunk vs function).
    assert e.accuracy == 1.0


def test_compare_vtable_thunk_chain_resolution():
    """Bad ILT aliases may jmp through an unregistered mid-.text stub before the
    real ILT entry and function body (Imperialism 0x40740f -> 0x490630 -> …)."""

    # orig layout:
    #   0x00 function body
    #   0x04 bad ILT THUNK -> 0x10
    #   0x10 mid .text E9 -> 0x18 (not in entity DB)
    #   0x18 good ILT THUNK -> 0x00
    #   0x40 vtable slot -> 0x04
    orig_mem = (
        b"\xc3\x00\x00\x00"  # function@0
        + b"\xe9\x07\x00\x00\x00"  # bad ILT@4: jmp 0x10
        + b"\x90\x90\x90\x90\x90\x90"  # pad to 0x10
        + b"\xe9\x03\x00\x00\x00"  # mid@0x10: jmp 0x18
        + b"\xe9\xe3\xff\xff\xff"  # good ILT@0x18: jmp 0x00
        + b"\x00" * (0x3C - 0x1D)
        + b"\x04\x00\x00\x00"  # vtable@0x3c
        + b"\x00" * 4  # pad so size-4 read at 0x3c fits
    )
    recomp_mem = b"\xcc" * 4 + b"\x08\x00\x00\x00" + b"\xc3"  # vtable@4 -> func@8

    orig_bin = RawImage.from_memory(orig_mem)
    recomp_bin = RawImage.from_memory(recomp_mem)

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.ORIG, 0x00, type=EntityType.FUNCTION, name="func", size=1)
        batch.set(ImageId.RECOMP, 0x08, type=EntityType.FUNCTION, name="func", size=1)
        batch.set(ImageId.ORIG, 0x04, type=EntityType.THUNK, name="bad_ilt", ref=0x10)
        batch.set(ImageId.ORIG, 0x18, type=EntityType.THUNK, name="good_ilt", ref=0x00)
        batch.set(ImageId.RECOMP, 0x04, type=EntityType.VTABLE, name="hello", size=4)
        batch.match(0x00, 0x08)
        batch.match(0x3C, 0x04)

    report = to_report(compare)

    e = report.entities["0x3c"]
    assert e is not None
    assert e.accuracy == 1.0


def test_compare_vtable_null_orig_slot():
    """Literal NULL slots in the orig vtable (MSVC cannot emit mid-table NULLs)."""

    orig_mem = b"\x00\x00\x00\x00" + b"\x04\x00\x00\x00" + b"\xc3\x00\x00\x00"
    recomp_mem = b"\xcc" * 4 + b"\xde\xad\xbe\xef" + b"\x08\x00\x00\x00" + b"\xc3"

    orig_bin = RawImage.from_memory(orig_mem)
    recomp_bin = RawImage.from_memory(recomp_mem)

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(ImageId.ORIG, 0x04, type=EntityType.FUNCTION, name="func", size=1)
        batch.set(ImageId.RECOMP, 0x08, type=EntityType.FUNCTION, name="func", size=1)
        batch.set(ImageId.ORIG, 0x00, type=EntityType.VTABLE, name="hello", size=8)
        batch.set(ImageId.RECOMP, 0x04, type=EntityType.VTABLE, name="hello", size=8)
        batch.match(0x04, 0x08)
        batch.match(0x00, 0x04)

    report = to_report(compare)

    e = report.entities["0x0"]
    assert e is not None
    assert e.accuracy == 1.0


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
    entity = report.entities[0]

    # The function matches, it has no diff data.
    assert entity.udiff is None
    assert entity.rdiff is None

    # We should be able to serialize with and without diff data.
    serialize_reccmp_report(report, diff_included=False)
    serialize_reccmp_report(report, diff_included=True)


def test_report_function_alignment():
    def test_entity(
        orig_addr: int, recomp_addr: int, entity_type: EntityType
    ) -> tuple[int, ReccmpComparedEntity]:
        return (
            orig_addr,
            ReccmpComparedEntity(
                orig_addr=orig_addr,
                recomp_addr=recomp_addr,
                name="hello",
                accuracy=1.0,
                type=entity_type,
            ),
        )

    report = ReccmpStatusReport(filename="test")

    # Baseline
    report.entities = {}
    assert report_function_alignment(report) == 0

    # Non-contiguous alignment allowed
    report.entities = dict(
        [
            test_entity(0, 0, EntityType.FUNCTION),
            test_entity(1, 4, EntityType.FUNCTION),
            test_entity(5, 5, EntityType.FUNCTION),
        ]
    )
    assert report_function_alignment(report) == 2

    # Vtables ignored
    report.entities = dict(
        [
            test_entity(0, 0, EntityType.FUNCTION),
            test_entity(5, 5, EntityType.VTABLE),
        ]
    )
    assert report_function_alignment(report) == 1


def test_report_function_accuracy():
    def test_entity(
        addr: int,
        entity_type: EntityType | None,
        accuracy: float,
        *,
        effective: bool = False,
        stub: bool = False,
    ) -> tuple[int, ReccmpComparedEntity]:
        return (
            addr,
            ReccmpComparedEntity(
                orig_addr=addr,
                recomp_addr=addr,
                name="hello",
                accuracy=accuracy,
                type=entity_type,
                is_stub=stub,
                is_effective_match=effective,
            ),
        )

    report = ReccmpStatusReport(filename="test")

    # Baseline
    report.entities = {}
    assert report_function_accuracy(report) == (0, 0, 0)

    # All matching
    report.entities = dict(
        [
            test_entity(0, EntityType.FUNCTION, 1.0),
            test_entity(1, EntityType.FUNCTION, 1.0),
        ]
    )
    assert report_function_accuracy(report) == (2, 2.0, 2.0)

    # Some diffs
    report.entities = dict(
        [
            test_entity(0, EntityType.FUNCTION, 1.0),
            test_entity(1, EntityType.FUNCTION, 0.5),
        ]
    )
    assert report_function_accuracy(report) == (2, 1.5, 1.5)

    # Effective match
    report.entities = dict(
        [
            test_entity(0, EntityType.FUNCTION, 1.0),
            test_entity(1, EntityType.FUNCTION, 0.5, effective=True),
        ]
    )
    assert report_function_accuracy(report) == (2, 1.5, 2.0)

    # Stubs ignored
    report.entities = dict(
        [
            test_entity(0, EntityType.FUNCTION, 0.8),
            test_entity(1, EntityType.FUNCTION, 0.5, stub=True),
        ]
    )
    assert report_function_accuracy(report) == (1, 0.8, 0.8)

    # Vtables ignored
    report.entities = dict(
        [
            test_entity(0, EntityType.VTABLE, 1.0),
        ]
    )
    assert report_function_accuracy(report) == (0, 0, 0)

    # Assumes type=None is a function.
    # This is to preserve compatibility with files that existed before #392.
    report.entities = dict(
        [
            test_entity(0, EntityType.FUNCTION, 1.0),
            test_entity(1, None, 0.5),
        ]
    )
    assert report_function_accuracy(report) == (2, 1.5, 1.5)


def test_compare_vtable_recomp_longer():
    """An extra virtual function on the recomp side should appear in the
    diff when the orig vtable size is known."""
    base_addr = 0x400000
    function_bytes = b"\xc3\x00\x00\x00"  # `ret` padded to 4 bytes
    functions = function_bytes + function_bytes

    func0_ptr = base_addr.to_bytes(4, "little")
    func1_ptr = (base_addr + 4).to_bytes(4, "little")

    # Orig has one virtual function; recomp has a second one.
    orig_mem = functions + func0_ptr
    recomp_mem = functions + func0_ptr + func1_ptr

    orig_bin = RawImage.from_memory(orig_mem, base_addr=base_addr)
    recomp_bin = RawImage.from_memory(recomp_mem, base_addr=base_addr)

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(
            ImageId.RECOMP, base_addr, type=EntityType.FUNCTION, name="func0", size=1
        )
        batch.set(
            ImageId.RECOMP,
            base_addr + 4,
            type=EntityType.FUNCTION,
            name="func1",
            size=1,
        )
        batch.set(
            ImageId.ORIG, base_addr + 8, type=EntityType.VTABLE, name="hello", size=4
        )
        batch.set(
            ImageId.RECOMP, base_addr + 8, type=EntityType.VTABLE, name="hello", size=8
        )
        batch.match(base_addr, base_addr)
        batch.match(base_addr + 4, base_addr + 4)
        batch.match(base_addr + 8, base_addr + 8)

    report = to_report(compare)
    e = report.entities[base_addr + 8]
    assert e is not None

    # The extra entry shows up in the diff and makes the match fail.
    assert e.accuracy != 1.0

    udiff = get_udiff(e)
    assert udiff is not None
    rendered = repr(udiff)
    assert "vtable0x04" in rendered
    assert "func1" in rendered


def test_compare_vtable_recomp_trailing_padding():
    """Alignment padding after the recomp vtable should not show up in the
    diff as an extra virtual function."""
    base_addr = 0x400000
    function_bytes = b"\xc3\x00\x00\x00"  # `ret` padded to 4 bytes
    padding = b"\x00\x00\x00\x00"

    func0_ptr = base_addr.to_bytes(4, "little")

    # Both tables hold one virtual function followed by an alignment slot.
    orig_mem = function_bytes + func0_ptr + padding
    recomp_mem = function_bytes + func0_ptr + padding

    orig_bin = RawImage.from_memory(orig_mem, base_addr=base_addr)
    recomp_bin = RawImage.from_memory(recomp_mem, base_addr=base_addr)

    pdb = Mock(spec=CvdumpAnalysis)
    compare = Compare(orig_bin, recomp_bin, pdb, "HELLO")

    with get_db(compare).batch() as batch:
        batch.set(
            ImageId.RECOMP, base_addr, type=EntityType.FUNCTION, name="func0", size=1
        )
        batch.set(
            ImageId.ORIG, base_addr + 4, type=EntityType.VTABLE, name="hello", size=4
        )
        # The recomp size includes the alignment padding after the table.
        batch.set(
            ImageId.RECOMP, base_addr + 4, type=EntityType.VTABLE, name="hello", size=8
        )
        batch.match(base_addr, base_addr)
        batch.match(base_addr + 4, base_addr + 4)

    report = to_report(compare)
    e = report.entities[base_addr + 4]
    assert e is not None

    # The padding is ignored, so the two tables match.
    assert e.accuracy == 1.0

    udiff = get_udiff(e)
    assert udiff is not None
    assert udiff == [
        (
            "@@ -vtable0x00,1 +vtable0x00,1 @@",
            [
                {
                    "both": [
                        ("vtable0x00", "(0x400000 / 0x400000)  :  func0", "vtable0x00")
                    ]
                }
            ],
        )
    ]
