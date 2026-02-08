"""Converting scalar types (CvdumpTypeKey) into the corresponding type name in Ghidra."""

from reccmp.cvdump.cvinfo import get_cvinfo, CvdumpTypeKey


_scalar_type_map = {
    "T_RCHAR": "char",
    "T_INT4": "int",
    "T_UINT4": "uint",
    "T_REAL32": "float",
    "T_REAL64": "double",
}


def scalar_type_to_cpp(type_key: CvdumpTypeKey) -> str:
    """Return the Ghidra name for the given scalar type."""
    cvtype = get_cvinfo(type_key)

    if cvtype.name.startswith("T_32P"):
        assert cvtype.pointer is not None
        return f"{scalar_type_to_cpp(cvtype.pointer)} *"

    # Removing the "T_" prefix is good enough for most types.
    # Some types require special handling via _scalar_type_map.
    return _scalar_type_map.get(cvtype.name, cvtype.name[2:].lower())
