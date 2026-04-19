# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

from typing import TYPE_CHECKING

import pytest
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey, CvdumpTypeMap
from reccmp.ghidra.importer.exceptions import TypeNotFoundError, TypeNotImplementedError
from .ghidra_integration_test_setup import GhidraTypeTestHelper
from .helpers import assert_instance

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import DataType


# Shortened version of a BETA10 recompilation
# codespell:ignore-begin
CVDUMP_TYPES = """
0x1199 : Length = 10, Leaf = 0x1002 LF_POINTER
	const Pointer (NEAR32), Size: 0
	Element type : T_RCHAR(0070)

0x12c8 : Length = 42, Leaf = 0x1505 LF_STRUCTURE
	# members = 0,  field list type 0x0000, FORWARD REF,
	Derivation list type 0x0000, VT shape type 0x0000
	Size = 0, class name = LegoAnimActorEntry, UDT(0x00006081)

0x12c9 : Length = 10, Leaf = 0x1002 LF_POINTER
	Pointer (NEAR32), Size: 0
	Element type : 0x12C8

0x12cd : Length = 314, Leaf = 0x1203 LF_FIELDLIST
    list[10] = LF_MEMBER, protected, type = T_LONG(0012), offset = 8
		member name = 'm_duration'
	list[11] = LF_MEMBER, protected, type = 0x12C9, offset = 12
		member name = 'm_modelList'
	list[12] = LF_MEMBER, protected, type = T_ULONG(0022), offset = 16
		member name = 'm_numActors'

0x12cf : Length = 30, Leaf = 0x1504 LF_CLASS
	# members = 15,  field list type 0x12cd, CONSTRUCTOR,
	Derivation list type 0x0000, VT shape type 0x12ce
	Size = 24, class name = LegoAnim, UDT(0x000012cf)

0x147f : Length = 74, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_MEMBER, public, type = T_ULONG(0022), offset = 0
		member name = 'LowPart'
	list[1] = LF_MEMBER, public, type = T_LONG(0012), offset = 4
		member name = 'HighPart'
	list[2] = LF_MEMBER, public, type = 0x147E, offset = 0
		member name = 'u'
	list[3] = LF_MEMBER, public, type = T_QUAD(0013), offset = 0
		member name = 'QuadPart'

0x1480 : Length = 30, Leaf = 0x1506 LF_UNION
	# members = 4,  field list type 0x147f, Size = 8	,class name = _LARGE_INTEGER, UDT(0x00001480)

0x3159 : Length = 30, Leaf = 0x1505 LF_STRUCTURE
	# members = 0,  field list type 0x0000, FORWARD REF,
	Derivation list type 0x0000, VT shape type 0x0000
	Size = 0, class name = HWND__

0x31bb : Length = 14, Leaf = 0x1503 LF_ARRAY
	Element type = T_ULONG(0022)
	Index type = T_SHORT(0011)
	length = 16
	Name =

0x4ef1 : Length = 18, Leaf = 0x1201 LF_ARGLIST argument count = 3
	list[0] = T_32PRCHAR(0470)
	list[1] = T_LONG(0012)
	list[2] = T_32PVOID(0403)

0x4ef2 : Length = 14, Leaf = 0x1008 LF_PROCEDURE
	Return type = T_VOID(0003), Call type = C Near
	Func attr = none
	# Parms = 3, Arg list type = 0x4ef1

0x5695 : Length = 50, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_ENUMERATE, public, value = (LF_CHAR) -1(0xFF), name = 'c_unknownminusone'
	list[1] = LF_ENUMERATE, public, value = 8, name = 'c_unknown8'

0x5696 : Length = 42, Leaf = 0x1507 LF_ENUM
	# members = 2,  type = T_INT4(0074) field list type 0x5695
NESTED, 	enum name = LegoCarBuild::Unknown0xf8, UDT(0x00005696)

0x6080 : Length = 62, Leaf = 0x1203 LF_FIELDLIST
	list[1] = LF_MEMBER, public, type = T_32PRCHAR(0470), offset = 0
		member name = 'm_name'
	list[2] = LF_MEMBER, public, type = T_ULONG(0022), offset = 4
		member name = 'm_type'

0x6081 : Length = 42, Leaf = 0x1505 LF_STRUCTURE
	# members = 3,  field list type 0x6080,
	Derivation list type 0x0000, VT shape type 0x0000
	Size = 8, class name = LegoAnimActorEntry, UDT(0x00006081)

0x608e : Length = 130, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_ENUMERATE, public, value = 0, name = 'c_initial'
	list[1] = LF_ENUMERATE, public, value = 1, name = 'c_ready'
	list[2] = LF_ENUMERATE, public, value = 2, name = 'c_hit'
	list[3] = LF_ENUMERATE, public, value = 3, name = 'c_hitAnimation'
	list[4] = LF_ENUMERATE, public, value = 4, name = 'c_disabled'
	list[5] = LF_ENUMERATE, public, value = 255, name = 'c_maxState'
	list[6] = LF_ENUMERATE, public, value = 256, name = 'c_noCollide'

0x608f : Length = 42, Leaf = 0x1507 LF_ENUM
	# members = 7,  type = T_INT4(0074) field list type 0x608e
NESTED, 	enum name = LegoPathActor::ActorState, UDT(0x0000608f)
"""
# codespell:ignore-end

pointer_to_char_key = CvdumpTypeKey(0x1199)
legoanimactor_forward_ref_key = CvdumpTypeKey(0x12C8)
legoanimactor_pointer_key = CvdumpTypeKey(0x12C9)
union_key = CvdumpTypeKey(0x1480)
hwnd_key = CvdumpTypeKey(0x3159)
array_key = CvdumpTypeKey(0x31BB)
procedure_key = CvdumpTypeKey(0x4EF2)
enum_with_negative_value_key = CvdumpTypeKey(0x5696)
legoanimactor_class_key = CvdumpTypeKey(0x6081)
enum_key = CvdumpTypeKey(0x608F)


def _assert_legoanimactorentry(imported_structure: "DataType"):
    from ghidra.program.model.data import Structure

    assert isinstance(imported_structure, Structure)

    assert imported_structure.getDisplayName() == "LegoAnimActorEntry"
    assert imported_structure.length == 8

    [name_component, id_component] = list(imported_structure.getComponents())
    assert name_component.getOffset() == 0
    assert name_component.getDataType().name == "char *"
    assert id_component.getOffset() == 4
    assert id_component.getDataType().name == "ulong"


verified_types = (
    t
    for t in CVInfoTypeEnum
    if CvdumpTypeMap[t].verified and t != CVInfoTypeEnum.T_NOTYPE
)


@pytest.mark.parametrize("scalar_type", verified_types)
def test_ghidra_scalar_types(
    type_helper: GhidraTypeTestHelper, scalar_type: CVInfoTypeEnum
):
    from ghidra.program.model.data import Pointer

    cv_type_info = CvdumpTypeMap[scalar_type]

    ghidra_type = type_helper.type_importer.import_pdb_type_into_ghidra(scalar_type)
    assert ghidra_type.length == cv_type_info.size

    if cv_type_info.pointer is not None:
        assert isinstance(ghidra_type, Pointer)

    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(scalar_type)
    assert second_import == ghidra_type


def test_ghidra_type_not_found(type_helper: GhidraTypeTestHelper):
    with pytest.raises(TypeNotFoundError, match="Failed to find referenced type"):
        type_helper.type_importer.import_pdb_type_into_ghidra(CvdumpTypeKey(0x1001))


def test_ghidra_type_class(type_helper: GhidraTypeTestHelper):
    type_helper.set_up_cvdump_types(CVDUMP_TYPES)
    imported_structure = type_helper.type_importer.import_pdb_type_into_ghidra(
        legoanimactor_class_key
    )
    _assert_legoanimactorentry(imported_structure)

    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(
        legoanimactor_class_key
    )
    assert second_import == imported_structure


def test_ghidra_verify_test_isolation(ghidra: "FlatProgramAPI"):
    """Make sure that the `LegoAnimActorEntry` created above was rolled back."""
    assert not list(ghidra.getDataTypes("LegoAnimActorEntry"))


def test_ghidra_forward_ref_to_pdb_type(type_helper: GhidraTypeTestHelper):
    type_helper.set_up_cvdump_types(CVDUMP_TYPES)
    imported_structure = type_helper.type_importer.import_pdb_type_into_ghidra(
        legoanimactor_forward_ref_key
    )
    _assert_legoanimactorentry(imported_structure)

    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(
        legoanimactor_forward_ref_key
    )
    assert second_import == imported_structure


def test_forward_ref_to_missing_type(type_helper: GhidraTypeTestHelper):
    type_helper.set_up_cvdump_types(CVDUMP_TYPES)

    with pytest.raises(
        TypeNotImplementedError,
        match="forward ref without target, needs to be created manually:",
    ):
        type_helper.type_importer.import_pdb_type_into_ghidra(hwnd_key)


def test_forward_ref_to_pre_existing_type(
    ghidra: "FlatProgramAPI", type_helper: GhidraTypeTestHelper
):
    data_type_manager = ghidra.getCurrentProgram().getDataTypeManager()
    from ghidra.program.model.data import (
        TypedefDataType,
        VoidDataType,
        DataTypeConflictHandler,
    )

    hwnd = data_type_manager.addDataType(
        TypedefDataType("HWND__", VoidDataType()), DataTypeConflictHandler.KEEP_HANDLER
    )

    type_helper.set_up_cvdump_types(CVDUMP_TYPES)

    imported_hwnd = type_helper.type_importer.import_pdb_type_into_ghidra(hwnd_key)
    assert imported_hwnd == hwnd


def test_ghidra_pointer_to_class(type_helper: GhidraTypeTestHelper):
    from ghidra.program.model.data import Pointer

    type_helper.set_up_cvdump_types(CVDUMP_TYPES)
    imported_pointer = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(
            legoanimactor_pointer_key
        ),
        Pointer,
    )
    _assert_legoanimactorentry(imported_pointer.dataType)

    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(
        legoanimactor_pointer_key
    )
    assert second_import == imported_pointer


def test_pointer_to_scalar(type_helper: GhidraTypeTestHelper):
    from ghidra.program.model.data import Pointer

    type_helper.set_up_cvdump_types(CVDUMP_TYPES)
    imported_pointer = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(pointer_to_char_key),
        Pointer,
    )
    assert (
        imported_pointer.dataType
        == type_helper.type_importer.import_pdb_type_into_ghidra(CVInfoTypeEnum.T_CHAR)
    )

    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(
        pointer_to_char_key
    )
    assert second_import == imported_pointer


def test_array(type_helper: GhidraTypeTestHelper):
    from ghidra.program.model.data import Array

    type_helper.set_up_cvdump_types(CVDUMP_TYPES)

    imported_array = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(array_key), Array
    )

    assert imported_array.getLength() == 16
    assert imported_array.getElementLength() == 4
    assert (
        imported_array.getDataType()
        == type_helper.type_importer.import_pdb_type_into_ghidra(CVInfoTypeEnum.T_ULONG)
    )

    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(array_key)
    assert second_import == imported_array


def test_enum(type_helper: GhidraTypeTestHelper):
    from ghidra.program.model.data import Enum

    type_helper.set_up_cvdump_types(CVDUMP_TYPES)

    imported_enum = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(enum_key), Enum
    )
    assert imported_enum.getDisplayName() == "ActorState"
    assert imported_enum.getCount() == 7
    assert list(imported_enum.getNames()) == [
        "c_initial",
        "c_ready",
        "c_hit",
        "c_hitAnimation",
        "c_disabled",
        "c_maxState",
        "c_noCollide",
    ]
    assert list(imported_enum.getValues()) == [
        0,
        1,
        2,
        3,
        4,
        255,
        256,
    ]

    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(enum_key)
    assert second_import == imported_enum


def test_enum_with_negative_value(type_helper: GhidraTypeTestHelper):
    from ghidra.program.model.data import Enum

    type_helper.set_up_cvdump_types(CVDUMP_TYPES)

    imported_enum = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(
            enum_with_negative_value_key
        ),
        Enum,
    )
    assert imported_enum.getDisplayName() == "Unknown0xf8"
    assert imported_enum.getCount() == 2
    assert list(imported_enum.getNames()) == ["c_unknownminusone", "c_unknown8"]
    assert list(imported_enum.getValues()) == [-1, 8]

    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(
        enum_with_negative_value_key
    )
    assert second_import == imported_enum


def test_fallback_procedure_import(type_helper: GhidraTypeTestHelper):
    """The feature is not fully implemented. This test asserts on the fallback behaviour."""

    type_helper.set_up_cvdump_types(CVDUMP_TYPES)

    imported_type = type_helper.type_importer.import_pdb_type_into_ghidra(procedure_key)
    # Fallback behaviour. This assertion should be changed if proper support is implemented
    assert imported_type == type_helper.type_importer.import_pdb_type_into_ghidra(
        CVInfoTypeEnum.T_VOID
    )

    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(procedure_key)
    assert second_import == imported_type


@pytest.mark.xfail(reason="Union import not yet implemented")
def test_union(type_helper: GhidraTypeTestHelper):
    from ghidra.program.model.data import Union

    type_helper.set_up_cvdump_types(CVDUMP_TYPES)

    _imported_union = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(union_key), Union
    )

    # More assertions are needed once we have proper support
