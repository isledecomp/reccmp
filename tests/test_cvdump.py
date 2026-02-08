import pytest
from reccmp.cvdump.cvinfo import (
    CVInfoTypeEnum,
    CvdumpTypeKey,
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
SCALARS_WITH_NORMALIZED_ID = (
    (CVInfoTypeEnum.T_32PINT4,      4,  False,  True),
    (CVInfoTypeEnum.T_32PLONG,      4,  False,  True),
    (CVInfoTypeEnum.T_32PRCHAR,     4,  False,  True),
    (CVInfoTypeEnum.T_32PREAL32,    4,  False,  True),
    (CVInfoTypeEnum.T_32PUCHAR,     4,  False,  True),
    (CVInfoTypeEnum.T_32PUINT4,     4,  False,  True),
    (CVInfoTypeEnum.T_32PULONG,     4,  False,  True),
    (CVInfoTypeEnum.T_32PUSHORT,    4,  False,  True),
    (CVInfoTypeEnum.T_32PVOID,      4,  False,  True),
    (CVInfoTypeEnum.T_BOOL08,       1,  False,  False),
    (CVInfoTypeEnum.T_CHAR,         1,  True,   False),
    (CVInfoTypeEnum.T_INT4,         4,  True,   False),
    (CVInfoTypeEnum.T_LONG,         4,  True,   False),
    (CVInfoTypeEnum.T_QUAD,         8,  True,   False),
    (CVInfoTypeEnum.T_RCHAR,        1,  True,   False),
    (CVInfoTypeEnum.T_REAL32,       4,  False,  False),
    (CVInfoTypeEnum.T_REAL64,       8,  False,  False),
    (CVInfoTypeEnum.T_SHORT,        2,  True,   False),
    (CVInfoTypeEnum.T_UCHAR,        1,  False,  False),
    (CVInfoTypeEnum.T_UINT4,        4,  False,  False),
    (CVInfoTypeEnum.T_ULONG,        4,  False,  False),
    (CVInfoTypeEnum.T_UQUAD,        8,  False,  False),
    (CVInfoTypeEnum.T_USHORT,       2,  False,  False),
    (CVInfoTypeEnum.T_WCHAR,        2,  False,  False),
)
# fmt: on


@pytest.mark.parametrize("type_key, size, _, __", SCALARS_WITH_NORMALIZED_ID)
def test_scalar_size(type_key: CvdumpTypeKey, size: int, _, __):
    assert scalar_type_size(type_key) == size


@pytest.mark.parametrize("type_key, _, is_signed, __", SCALARS_WITH_NORMALIZED_ID)
def test_scalar_signed(type_key: CvdumpTypeKey, _, is_signed: bool, __):
    assert scalar_type_signed(type_key) == is_signed


@pytest.mark.parametrize("type_key, _, __, is_pointer", SCALARS_WITH_NORMALIZED_ID)
def test_scalar_pointer(type_key: CvdumpTypeKey, _, __, is_pointer: bool):
    assert scalar_type_pointer(type_key) == is_pointer
