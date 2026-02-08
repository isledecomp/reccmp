import pytest
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey
from reccmp.ghidra.importer.type_conversion import scalar_type_to_cpp

SAMPLES = (
    # Pointers
    (CVInfoTypeEnum.T_32PCHAR, "char *"),
    (CVInfoTypeEnum.T_32PINT4, "int *"),
    (CVInfoTypeEnum.T_32PLONG, "long *"),
    (CVInfoTypeEnum.T_32PRCHAR, "char *"),
    (CVInfoTypeEnum.T_32PREAL32, "float *"),
    (CVInfoTypeEnum.T_32PREAL64, "double *"),
    (CVInfoTypeEnum.T_32PSHORT, "short *"),
    (CVInfoTypeEnum.T_32PUCHAR, "uchar *"),
    (CVInfoTypeEnum.T_32PUINT4, "uint *"),
    (CVInfoTypeEnum.T_32PULONG, "ulong *"),
    (CVInfoTypeEnum.T_32PUSHORT, "ushort *"),
    # Scalars
    (CVInfoTypeEnum.T_CHAR, "char"),
    (CVInfoTypeEnum.T_INT4, "int"),
    (CVInfoTypeEnum.T_LONG, "long"),
    (CVInfoTypeEnum.T_RCHAR, "char"),
    (CVInfoTypeEnum.T_REAL32, "float"),
    (CVInfoTypeEnum.T_REAL64, "double"),
    (CVInfoTypeEnum.T_SHORT, "short"),
    (CVInfoTypeEnum.T_UCHAR, "uchar"),
    (CVInfoTypeEnum.T_UINT4, "uint"),
    (CVInfoTypeEnum.T_ULONG, "ulong"),
    (CVInfoTypeEnum.T_USHORT, "ushort"),
)


@pytest.mark.parametrize("key, type_name", SAMPLES)
def test_ghidra_type_conversion(key: CvdumpTypeKey, type_name: str):
    assert scalar_type_to_cpp(key) == type_name
