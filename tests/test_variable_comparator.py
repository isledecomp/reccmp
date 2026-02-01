import pytest
from reccmp.compare.variables import VariableComparator, CompareResult
from reccmp.cvdump.types import (
    CvdumpTypeKey,
    CvdumpTypesParser,
)
from reccmp.compare.db import EntityDb, ReccmpMatch
from reccmp.types import EntityType
from .raw_image import RawImage


def get_match(db: EntityDb, orig_addr: int) -> ReccmpMatch:
    """Helper to ensure we get a matched ReccmpEntity.
    Intended to protect against changes to the Entity DB API."""
    m = db.get_one_match(orig_addr)
    assert m is not None
    return m


class ScalarTypeId:
    """Future-proofing a change to CvdumpTypeKey from str to int"""

    T_CHAR: CvdumpTypeKey = "T_CHAR(0010)"
    T_INT4: CvdumpTypeKey = "T_INT4(0074)"
    T_32PRCHAR: CvdumpTypeKey = "T_32PRCHAR(0470)"


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.fixture(name="types")
def fixture_types() -> CvdumpTypesParser:
    return CvdumpTypesParser()


def create_matched_variable(
    db: EntityDb,
    addr: int,
    *,
    size: int | None = None,
    data_type: CvdumpTypeKey | None = None,
):
    """Helper to create a matched entity for the variable.
    Intended to reduce boilerplate code in the tests."""
    with db.batch() as batch:
        batch.set_recomp(addr, type=EntityType.DATA, name=f"test_{addr:#04x}")
        if data_type is not None:
            batch.set_recomp(addr, data_type=data_type)

        if size is not None:
            batch.set_recomp(addr, size=size)

        batch.match(addr, addr)


def test_compare_scalar_match(db: EntityDb, types: CvdumpTypesParser):
    """Match on scalar variable with initialized data."""
    create_matched_variable(db, 0, data_type=ScalarTypeId.T_CHAR)

    orig = RawImage.from_memory(b"\x05")
    recomp = RawImage.from_memory(b"\x05")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_scalar_diff(db: EntityDb, types: CvdumpTypesParser):
    """Diff on scalar variable with initialized data."""
    create_matched_variable(db, 0, data_type=ScalarTypeId.T_CHAR)

    orig = RawImage.from_memory(b"\x05")
    recomp = RawImage.from_memory(b"\x07")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF


def test_compare_pointer_match(db: EntityDb, types: CvdumpTypesParser):
    """Match on scalar variable with initialized data."""
    create_matched_variable(db, 0, data_type=ScalarTypeId.T_32PRCHAR)
    # Entity at address 0x0004 required to match
    with db.batch() as batch:
        batch.set_recomp(4, name="Hello")
        batch.match(4, 4)

    orig = RawImage.from_memory(b"\x04\x00\x00\x00")
    recomp = RawImage.from_memory(b"\x04\x00\x00\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_pointer_diff(db: EntityDb, types: CvdumpTypesParser):
    """Diff on scalar variable with initialized data."""
    create_matched_variable(db, 0, data_type=ScalarTypeId.T_32PRCHAR)
    # Create the entity only on the recomp side.
    with db.batch() as batch:
        batch.set_recomp(4, name="Hello")

    orig = RawImage.from_memory(b"\x04\x00\x00\x00")
    recomp = RawImage.from_memory(b"\x04\x00\x00\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF

    # Verify pointer display
    (orig_value, recomp_value) = c.compared[0].values
    assert "Hello" not in orig_value
    assert "Hello" in recomp_value


def test_compare_null_pointer(db: EntityDb, types: CvdumpTypesParser):
    """Pointer variables set to zero in both binaries are matches."""
    create_matched_variable(db, 0, data_type=ScalarTypeId.T_32PRCHAR)

    orig = RawImage.from_memory(b"\x00\x00\x00\x00")
    recomp = RawImage.from_memory(b"\x00\x00\x00\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_prefer_datatype_size(db: EntityDb, types: CvdumpTypesParser):
    """Override the entity size with the data type size (if it is set)"""
    create_matched_variable(db, 0, size=2, data_type=ScalarTypeId.T_CHAR)

    # Second byte is different
    orig = RawImage.from_memory(b"\x05\x06")
    recomp = RawImage.from_memory(b"\x05\x07")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    # Should only compare the first byte
    assert c.result == CompareResult.MATCH


def test_compare_raw_match(db: EntityDb, types: CvdumpTypesParser):
    """Match on raw data."""
    # Size is required because it cannot be derived from the data type.
    create_matched_variable(db, 0, size=2)

    orig = RawImage.from_memory(b"\x12\x34")
    recomp = RawImage.from_memory(b"\x12\x34")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_raw_diff(db: EntityDb, types: CvdumpTypesParser):
    """Diff on raw data."""
    # Size is required because it cannot be derived from the data type.
    create_matched_variable(db, 0, size=2)

    orig = RawImage.from_memory(b"\x12\x34")
    recomp = RawImage.from_memory(b"\x55\x55")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    # Flag as a warning.
    # Without type info we have no way to know which offsets are pointers.
    assert c.result == CompareResult.WARN


def test_compare_scalar_bss_match(db: EntityDb, types: CvdumpTypesParser):
    """Match on scalar variable with uninitialized data."""
    create_matched_variable(db, 0, data_type=ScalarTypeId.T_CHAR)

    orig = RawImage.from_memory(size=1)
    recomp = RawImage.from_memory(size=1)
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_raw_bss_match(db: EntityDb, types: CvdumpTypesParser):
    """Match on raw data with uninitialized data."""
    # Size is required because it cannot be derived from the data type.
    create_matched_variable(db, 0, size=1)

    orig = RawImage.from_memory(size=10)
    recomp = RawImage.from_memory(size=10)
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_scalar_bss_diff(db: EntityDb, types: CvdumpTypesParser):
    """Scalar variable, one initialized to non-zero, one uninitialized."""
    create_matched_variable(db, 0, data_type=ScalarTypeId.T_CHAR)

    orig = RawImage.from_memory(size=1)  # bss
    recomp = RawImage.from_memory(b"\x01")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF


def test_compare_scalar_bss_effective_match(db: EntityDb, types: CvdumpTypesParser):
    """Scalar variable, one initialized to zero, one uninitialized.
    The initialized zero byte is in the BssState.MAYBE region."""
    create_matched_variable(db, 0, data_type=ScalarTypeId.T_CHAR)

    orig = RawImage.from_memory(size=1)  # bss
    recomp = RawImage.from_memory(b"\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_scalar_bss_true_diff(db: EntityDb, types: CvdumpTypesParser):
    """Scalar variable, one initialized to zero, one uninitialized.
    The initialized zero byte is in the BssState.NO region."""
    create_matched_variable(db, 0, data_type=ScalarTypeId.T_CHAR)

    orig = RawImage.from_memory(size=1)  # bss
    recomp = RawImage.from_memory(b"\x00\x01")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF
