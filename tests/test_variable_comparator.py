import pytest
from reccmp.compare.variables import VariableComparator, CompareResult
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey
from reccmp.cvdump.types import (
    CvdumpTypesParser,
    FieldListItem,
    TypeInfo,
)
from reccmp.compare.db import EntityDb, ReccmpMatch
from reccmp.types import EntityType
from .mock_types_db import MockTypesDb
from .raw_image import RawImage


def get_match(db: EntityDb, orig_addr: int) -> ReccmpMatch:
    """Helper to ensure we get a matched ReccmpEntity.
    Intended to protect against changes to the Entity DB API."""
    m = db.get_one_match(orig_addr)
    assert m is not None
    return m


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
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_CHAR)

    orig = RawImage.from_memory(b"\x05")
    recomp = RawImage.from_memory(b"\x05")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_scalar_diff(db: EntityDb, types: CvdumpTypesParser):
    """Diff on scalar variable with initialized data."""
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_CHAR)

    orig = RawImage.from_memory(b"\x05")
    recomp = RawImage.from_memory(b"\x07")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF


def test_compare_pointer_match(db: EntityDb, types: CvdumpTypesParser):
    """Match on scalar variable with initialized data."""
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_32PVOID)
    # Entity at address 0x0004 required to match
    with db.batch() as batch:
        batch.set_recomp(8, name="Hello")
        batch.match(4, 8)

    orig = RawImage.from_memory(b"\x04\x00\x00\x00")
    recomp = RawImage.from_memory(b"\x08\x00\x00\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_pointer_diff(db: EntityDb, types: CvdumpTypesParser):
    """Diff on scalar variable with initialized data."""
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_32PVOID)
    # Create the entity only on the recomp side.
    with db.batch() as batch:
        batch.set_recomp(8, name="Hello")

    orig = RawImage.from_memory(b"\x04\x00\x00\x00")
    recomp = RawImage.from_memory(b"\x08\x00\x00\x00")
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
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_32PVOID)

    orig = RawImage.from_memory(b"\x00\x00\x00\x00")
    recomp = RawImage.from_memory(b"\x00\x00\x00\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_prefer_datatype_size(db: EntityDb, types: CvdumpTypesParser):
    """Override the entity size with the data type size (if it is set)"""
    create_matched_variable(db, 0, size=2, data_type=CVInfoTypeEnum.T_CHAR)

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
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_CHAR)

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
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_CHAR)

    orig = RawImage.from_memory(size=1)  # bss
    recomp = RawImage.from_memory(b"\x01")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF


def test_compare_scalar_bss_effective_match(db: EntityDb, types: CvdumpTypesParser):
    """Scalar variable, one initialized to zero, one uninitialized.
    The initialized zero byte is in the BssState.MAYBE region."""
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_CHAR)

    orig = RawImage.from_memory(size=1)  # bss
    recomp = RawImage.from_memory(b"\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_scalar_bss_true_diff(db: EntityDb, types: CvdumpTypesParser):
    """Scalar variable, one initialized to zero, one uninitialized.
    The initialized zero byte is in the BssState.NO region."""
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_CHAR)

    orig = RawImage.from_memory(size=1)  # bss
    recomp = RawImage.from_memory(b"\x00\x01")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF


def test_compare_complex_partial_diff(db: EntityDb):
    """Each struct member or array offset can match or diff.
    The variable will only match if all members match."""
    key = CvdumpTypeKey(0x1000)
    type_info = [
        TypeInfo(
            key=key,
            size=4,
            members=[
                FieldListItem(offset=0, name="[0]", type=CVInfoTypeEnum.T_USHORT),
                FieldListItem(offset=2, name="[1]", type=CVInfoTypeEnum.T_USHORT),
            ],
        )
    ]

    types = MockTypesDb(type_info)
    create_matched_variable(db, 0, data_type=key)

    orig = RawImage.from_memory(b"\x01\x02\x03\x04")
    recomp = RawImage.from_memory(b"\x01\x02\x00\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF
    assert c.compared[0].match is True
    assert c.compared[1].match is False


def test_compare_complex_with_padding(db: EntityDb):
    """Make sure we report a diff if padding bytes don't match."""
    key = CvdumpTypeKey(0x1000)
    type_info = [
        TypeInfo(
            key=key,
            size=8,
            members=[
                FieldListItem(offset=0, name="m_test", type=CVInfoTypeEnum.T_INT4),
                FieldListItem(offset=4, name="m_short", type=CVInfoTypeEnum.T_USHORT),
                # 2 bytes of padding to cover the 8 byte footprint
            ],
        )
    ]

    types = MockTypesDb(type_info)
    create_matched_variable(db, 0, data_type=key)

    # Padding bytes are nonzero in orig
    orig = RawImage.from_memory(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    recomp = RawImage.from_memory(b"\x01\x02\x03\x04\x05\x06\x00\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF


@pytest.mark.xfail(reason="GH #305")
def test_compare_string_effective_match(db: EntityDb, types: CvdumpTypesParser):
    """If the datatype is a string, report a match if the text matches,
    regardless of whether the pointers match."""
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_32PRCHAR)

    orig = RawImage.from_memory(b"\x04\x00\x00\x00test\x00")
    recomp = RawImage.from_memory(b"\x06\x00\x00\x00\x00\x00test\x00")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_other_pointers_no_effective_match(
    db: EntityDb, types: CvdumpTypesParser
):
    """The above case `test_compare_string_effective_match` is true only for strings.
    Pointers to other scalar datatypes do not effectively match."""
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_32PINT4)

    orig = RawImage.from_memory(b"\x04\x00\x00\x00\x01\x02\x03\x04")
    recomp = RawImage.from_memory(b"\x06\x00\x00\x00\x00\x00\x01\x02\x03\x04")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.DIFF


@pytest.mark.xfail(reason="GH #308")
def test_compare_pointer_entity_offset(db: EntityDb, types: CvdumpTypesParser):
    """If a pointer variable points at the same offset to the same entity
    in both binaries, this is a match."""
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_32PVOID)
    with db.batch() as batch:
        batch.set_recomp(6, size=10, type=EntityType.DATA, name="hello")
        batch.match(4, 6)

    # Pointers each point to "hello+4"
    orig = RawImage.from_memory(b"\x08\x00\x00\x00", size=16)
    recomp = RawImage.from_memory(b"\x0a\x00\x00\x00", size=16)
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_complex_raw_missing_key(db: EntityDb, types: CvdumpTypesParser):
    """Compare raw data (using size attribute) if we cannot derive struct members."""
    key = CvdumpTypeKey(0x1000)
    create_matched_variable(db, 0, data_type=key, size=4)

    orig = RawImage.from_memory(b"\x01\x02\x03\x04")
    recomp = RawImage.from_memory(b"\x01\x02\x03\x04")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_complex_raw_empty_struct(db: EntityDb):
    """Compare raw data (using struct size) for structs or classes with no members."""
    key = CvdumpTypeKey(0x1000)
    type_info = [
        TypeInfo(
            key=key,
            size=4,
            members=[],
        )
    ]

    create_matched_variable(db, 0, data_type=key)
    types = MockTypesDb(type_info)

    orig = RawImage.from_memory(b"\x01\x02\x03\x04")
    recomp = RawImage.from_memory(b"\x01\x02\x03\x04")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.MATCH


def test_compare_orig_read_error(db: EntityDb, types: CvdumpTypesParser):
    """Trap a read error in the orig binary and report an error."""
    create_matched_variable(db, 0, data_type=CVInfoTypeEnum.T_INT4)

    # Needs at least one byte so the seek() call doesn't fail.
    orig = RawImage.from_memory(b"\x01")
    recomp = RawImage.from_memory(b"\x01\x02\x03\x04")
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.result == CompareResult.ERROR


DISPLAY_VALUES = (
    (b"\xff", CVInfoTypeEnum.T_CHAR, "-1"),
    (b"\xff", CVInfoTypeEnum.T_UCHAR, "255"),
    (b"\xff\xff", CVInfoTypeEnum.T_SHORT, "-1"),
    (b"\xff\xff", CVInfoTypeEnum.T_USHORT, "65535"),
    (b"\xff\xff\xff\xff", CVInfoTypeEnum.T_INT4, "-1"),
    (b"\xff\xff\xff\xff", CVInfoTypeEnum.T_UINT4, "4294967295"),
    (b"\x00\x00\x80\xbf", CVInfoTypeEnum.T_REAL32, "-1.0"),
    (b"\x00\x00\x80\x3f", CVInfoTypeEnum.T_REAL32, "1.0"),
    (b"\x00\x00\x00\x00\x00\x00\xf0\xbf", CVInfoTypeEnum.T_REAL64, "-1.0"),
    (b"\x00\x00\x00\x00\x00\x00\xf0\x3f", CVInfoTypeEnum.T_REAL64, "1.0"),
)


@pytest.mark.parametrize("data, type_key, text", DISPLAY_VALUES)
def test_display_signed_unsigned(
    db: EntityDb,
    types: CvdumpTypesParser,
    data: bytes,
    type_key: CvdumpTypeKey,
    text: str,
):
    """Make sure we display the correct text representation for various
    signed and unsigned variables."""
    create_matched_variable(db, 0, data_type=type_key)

    # This will report a diff for any nonzero value.
    orig = RawImage.from_memory(data)
    recomp = RawImage.from_memory(size=500)
    comparator = VariableComparator(db, types, orig, recomp)

    c = comparator.compare_variable(get_match(db, 0))

    assert c is not None
    assert c.compared[0].values[0] == text
