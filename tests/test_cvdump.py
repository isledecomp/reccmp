import pytest
from reccmp.cvdump.types import (
    CvdumpTypeKey,
    normalize_type_id,
    scalar_type_size,
    scalar_type_pointer,
    scalar_type_signed,
)

# These are all the types seen in the cvdump.
# We have char, short, int, long, long long, float, and double all represented
# in both signed and unsigned.
# We can also identify a 4 byte pointer with the T_32 prefix.
# The type T_VOID is used to designate a function's return type.
# T_NOTYPE is specified as the type of "this" for a static function in a class.

# For reference: https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h

# fmt: off
# Fields are: type_name, size, is_signed, is_pointer
type_check_cases = (
    ("T_32PINT4(0474)",      4,  False,  True),
    ("T_32PLONG(0412)",      4,  False,  True),
    ("T_32PRCHAR(0470)",     4,  False,  True),
    ("T_32PREAL32(0440)",    4,  False,  True),
    ("T_32PUCHAR(0420)",     4,  False,  True),
    ("T_32PUINT4(0475)",     4,  False,  True),
    ("T_32PULONG(0422)",     4,  False,  True),
    ("T_32PUSHORT(0421)",    4,  False,  True),
    ("T_32PVOID(0403)",      4,  False,  True),
    ("T_BOOL08(0030)",       1,  False,  False),
    ("T_CHAR(0010)",         1,  True,   False),
    ("T_INT4(0074)",         4,  True,   False),
    ("T_LONG(0012)",         4,  True,   False),
    ("T_QUAD(0013)",         8,  True,   False),
    ("T_RCHAR(0070)",        1,  True,   False),
    ("T_REAL32(0040)",       4,  False,  False),
    ("T_REAL64(0041)",       8,  False,  False),
    ("T_SHORT(0011)",        2,  True,   False),
    ("T_UCHAR(0020)",        1,  False,  False),
    ("T_UINT4(0075)",        4,  False,  False),
    ("T_ULONG(0022)",        4,  False,  False),
    ("T_UQUAD(0023)",        8,  False,  False),
    ("T_USHORT(0021)",       2,  False,  False),
    ("T_WCHAR(0071)",        2,  False,  False),
)
# fmt: on


SCALARS_WITH_NORMALIZED_ID = tuple(
    (normalize_type_id(type_name), size, is_signed, is_pointer)
    for type_name, size, is_signed, is_pointer in type_check_cases
)


@pytest.mark.parametrize("type_key, size, _, __", SCALARS_WITH_NORMALIZED_ID)
def test_scalar_size(type_key: CvdumpTypeKey, size: int, _, __):
    assert scalar_type_size(type_key) == size


@pytest.mark.parametrize("type_key, _, is_signed, __", SCALARS_WITH_NORMALIZED_ID)
def test_scalar_signed(type_key: CvdumpTypeKey, _, is_signed: bool, __):
    assert scalar_type_signed(type_key) == is_signed


@pytest.mark.parametrize("type_key, _, __, is_pointer", SCALARS_WITH_NORMALIZED_ID)
def test_scalar_pointer(type_key: CvdumpTypeKey, _, __, is_pointer: bool):
    assert scalar_type_pointer(type_key) == is_pointer
