"""Converting scalar types (CvdumpTypeKey) into the corresponding type name in Ghidra."""

from reccmp.cvdump.cvinfo import (
    CVInfoTypeEnum,
    CvdumpTypeMap,
    CvdumpTypeKey,
)


_scalar_type_map: dict[CvdumpTypeKey, str] = {
    CVInfoTypeEnum.T_HRESULT: "long",
    CVInfoTypeEnum.T_RCHAR: "char",
    CVInfoTypeEnum.T_INT4: "int",
    CVInfoTypeEnum.T_UINT4: "uint",
    CVInfoTypeEnum.T_QUAD: "longlong",
    CVInfoTypeEnum.T_UQUAD: "ulonglong",
    CVInfoTypeEnum.T_REAL32: "float",
    CVInfoTypeEnum.T_REAL64: "double",
    CVInfoTypeEnum.T_WCHAR: "wchar_t",
}


def scalar_type_to_cpp(type_key: CvdumpTypeKey) -> str:
    """Return the Ghidra name for the given scalar type."""
    cvtype = CvdumpTypeMap[type_key]

    # Removing the "T_" prefix is good enough for most types.
    # Some types require special handling via _scalar_type_map.
    return _scalar_type_map.get(type_key, cvtype.name[2:].lower())
