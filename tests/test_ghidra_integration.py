# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from reccmp.compare.core import Compare
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey, CvdumpTypeMap
from reccmp.cvdump.types import CvdumpParsedType, FieldListItem
from reccmp.ghidra.importer.exceptions import TypeNotFoundError
from reccmp.ghidra.importer.pdb_extraction import PdbFunctionExtractor
from tests.test_image_raw import RawImage

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI

verified_types = (
    t
    for t in CVInfoTypeEnum
    if CvdumpTypeMap[t].verified and t != CVInfoTypeEnum.T_NOTYPE
)


@pytest.mark.parametrize("scalar_type", verified_types)
def test_ghidra_scalar_types(ghidra, scalar_type):
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter
    from ghidra.program.model.data import Pointer

    type_importer = PdbTypeImporter(ghidra, Mock(), set())

    cv_type_info = CvdumpTypeMap[scalar_type]

    ghidra_type = type_importer.import_pdb_type_into_ghidra(scalar_type)
    assert ghidra_type.length == cv_type_info.size

    if cv_type_info.pointer is not None:
        assert isinstance(ghidra_type, Pointer)


def test_ghidra_type_not_found(ghidra: "FlatProgramAPI"):
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter

    compare = Compare(RawImage.from_memory(), RawImage.from_memory(), Mock(), "TEST")
    type_importer = PdbTypeImporter(ghidra, PdbFunctionExtractor(compare), set())

    with pytest.raises(TypeNotFoundError, match="Failed to find referenced type"):
        type_importer.import_pdb_type_into_ghidra(CvdumpTypeKey.from_str("0x1001"))


def test_ghidra_type_class(ghidra: "FlatProgramAPI"):
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter
    from ghidra.program.model.data import Structure

    field_list_key = CvdumpTypeKey.from_str("0x1001")
    class_key = CvdumpTypeKey.from_str("0x1002")
    compare = Compare(RawImage.from_memory(), RawImage.from_memory(), Mock(), "TEST")
    compare.types.keys[field_list_key] = CvdumpParsedType(
        type="LF_FIELDLIST",
        members=[
            FieldListItem(offset=0, name="id", type=CVInfoTypeEnum.T_INT4),
            FieldListItem(offset=4, name="name", type=CVInfoTypeEnum.T_32PCHAR),
        ],
    )
    compare.types.keys[class_key] = CvdumpParsedType(
        type="LF_CLASS", name="TestClass", field_list_type=field_list_key, size=8
    )
    type_importer = PdbTypeImporter(ghidra, PdbFunctionExtractor(compare), set())

    x = type_importer.import_pdb_type_into_ghidra(class_key)

    assert isinstance(x, Structure)
    assert x.length == 8

    [id_component, name_component] = list(x.getComponents())
    assert id_component.getOffset() == 0
    assert id_component.getDataType().name == "int"
    assert name_component.getOffset() == 4
    assert name_component.getDataType().name == "char *"


def test_ghidra_verify_test_isolation(ghidra: "FlatProgramAPI"):
    """Make sure that the `TestClass` created above was rolled back."""
    assert not list(ghidra.getDataTypes("TestClass"))
