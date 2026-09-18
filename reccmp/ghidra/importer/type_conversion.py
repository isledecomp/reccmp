"""Converting scalar types (CvdumpTypeKey) into the corresponding type name in Ghidra."""

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

from ghidra.program.model.data import (
    BooleanDataType,
    BuiltIn,
    LongDataType,
    VoidDataType,
    IntegerDataType,
    LongLongDataType,
    UnsignedLongLongDataType,
    CharDataType,
    ShortDataType,
    UnsignedCharDataType,
    UnsignedShortDataType,
    UnsignedIntegerDataType,
    UnsignedLongDataType,
    FloatDataType,
    DoubleDataType,
    WideCharDataType,
)

from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey
from reccmp.ghidra.importer.exceptions import TypeNotImplementedError

_scalar_type_map: dict[CvdumpTypeKey, BuiltIn] = {
    CVInfoTypeEnum.T_VOID: VoidDataType(),
    CVInfoTypeEnum.T_HRESULT: LongDataType(),
    CVInfoTypeEnum.T_CHAR: CharDataType(),
    CVInfoTypeEnum.T_SHORT: ShortDataType(),
    CVInfoTypeEnum.T_LONG: LongDataType(),
    CVInfoTypeEnum.T_QUAD: LongLongDataType(),
    CVInfoTypeEnum.T_UCHAR: UnsignedCharDataType(),
    CVInfoTypeEnum.T_USHORT: UnsignedShortDataType(),
    CVInfoTypeEnum.T_ULONG: UnsignedLongDataType(),
    CVInfoTypeEnum.T_UQUAD: UnsignedLongLongDataType(),
    CVInfoTypeEnum.T_REAL32: FloatDataType(),
    CVInfoTypeEnum.T_REAL64: DoubleDataType(),
    CVInfoTypeEnum.T_RCHAR: CharDataType(),
    CVInfoTypeEnum.T_WCHAR: WideCharDataType(),
    CVInfoTypeEnum.T_INT4: IntegerDataType(),
    CVInfoTypeEnum.T_UINT4: UnsignedIntegerDataType(),
    # C++ `bool` is 1 byte. Wider PDB "bool" scalars are not C++ bool
    # (Win32 BOOL is T_BOOL32 / T_INT4, SGP BOOLEAN is a typedef).
    CVInfoTypeEnum.T_BOOL08: BooleanDataType(),
    CVInfoTypeEnum.T_BOOL16: UnsignedShortDataType(),
    CVInfoTypeEnum.T_BOOL32: UnsignedIntegerDataType(),
    CVInfoTypeEnum.T_BOOL64: UnsignedLongLongDataType(),
    CVInfoTypeEnum.T_BOOL32FF: IntegerDataType(),
}


def get_scalar_ghidra_type(type_key: CvdumpTypeKey) -> "BuiltIn":
    """Return the Ghidra type for the given scalar Cvdump type."""
    result = _scalar_type_map.get(type_key)
    if result is not None:
        return result

    raise TypeNotImplementedError(
        f"Ghidra import for Cvdump type {type_key} is not implemented"
    )
