# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

from typing import TYPE_CHECKING, TypeVar
from unittest.mock import Mock

import pytest
from reccmp.compare.core import Compare
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey, CvdumpTypeMap
from reccmp.cvdump.types import (
    CvdumpParsedType,
    EnumItem,
    FieldListItem,
    VirtualBaseClass,
    VirtualBasePointer,
)
from reccmp.ghidra.importer.exceptions import TypeNotFoundError, TypeNotImplementedError
from reccmp.ghidra.importer.pdb_extraction import PdbFunctionExtractor
from tests.test_image_raw import RawImage

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import DataType
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter

verified_types = (
    t
    for t in CVInfoTypeEnum
    if CvdumpTypeMap[t].verified and t != CVInfoTypeEnum.T_NOTYPE
)


# TODO: Move to a general helper file

T = TypeVar("T")


def assert_instance(value: object, expected_class: type[T]) -> T:
    """Type narrowing does not work well in the IDE for some reason, this makes it explicit"""
    assert isinstance(value, expected_class)
    return value


@pytest.fixture(name="type_importer", scope="function")
def pdb_type_importer_fixture(ghidra: "FlatProgramAPI"):
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter

    compare = Compare(RawImage.from_memory(), RawImage.from_memory(), Mock(), "TEST")
    type_importer = PdbTypeImporter(ghidra, PdbFunctionExtractor(compare), set())
    yield type_importer


@pytest.mark.parametrize("scalar_type", verified_types)
def test_ghidra_scalar_types(
    type_importer: "PdbTypeImporter", scalar_type: CVInfoTypeEnum
):
    from ghidra.program.model.data import Pointer

    cv_type_info = CvdumpTypeMap[scalar_type]

    ghidra_type = type_importer.import_pdb_type_into_ghidra(scalar_type)
    assert ghidra_type.length == cv_type_info.size

    if cv_type_info.pointer is not None:
        assert isinstance(ghidra_type, Pointer)


def test_ghidra_type_not_found(type_importer: "PdbTypeImporter"):
    with pytest.raises(TypeNotFoundError, match="Failed to find referenced type"):
        type_importer.import_pdb_type_into_ghidra(CvdumpTypeKey.from_str("0x1001"))


forward_ref_key = CvdumpTypeKey.from_str("0x1001")
class_field_list_key = CvdumpTypeKey.from_str("0x1002")
class_key = CvdumpTypeKey.from_str("0x1003")
pointer_to_class_key = CvdumpTypeKey.from_str("0x1004")


def _set_up_test_class(compare: Compare):
    compare.types.keys[forward_ref_key] = CvdumpParsedType(
        type="LF_CLASS",
        name="TestClass",
        field_list_type=CVInfoTypeEnum.T_NOTYPE,
        size=0,
        udt=class_key,
        is_forward_ref=True,
    )
    compare.types.keys[class_field_list_key] = CvdumpParsedType(
        type="LF_FIELDLIST",
        members=[
            FieldListItem(offset=0, name="id", type=CVInfoTypeEnum.T_INT4),
            FieldListItem(offset=4, name="name", type=CVInfoTypeEnum.T_32PCHAR),
        ],
    )
    compare.types.keys[class_key] = CvdumpParsedType(
        type="LF_CLASS", name="TestClass", field_list_type=class_field_list_key, size=8
    )
    compare.types.keys[pointer_to_class_key] = CvdumpParsedType(
        type="LF_POINTER", element_type=class_key
    )


def _assert_test_class(imported_structure: "DataType"):
    from ghidra.program.model.data import Structure

    assert isinstance(imported_structure, Structure)

    assert imported_structure.getDisplayName() == "TestClass"
    assert imported_structure.length == 8

    [id_component, name_component] = list(imported_structure.getComponents())
    assert id_component.getOffset() == 0
    assert id_component.getDataType().name == "int"
    assert name_component.getOffset() == 4
    assert name_component.getDataType().name == "char *"


def test_ghidra_type_class(type_importer: "PdbTypeImporter"):
    _set_up_test_class(type_importer.extraction.compare)
    imported_structure = type_importer.import_pdb_type_into_ghidra(class_key)
    _assert_test_class(imported_structure)


def test_ghidra_verify_test_isolation(ghidra: "FlatProgramAPI"):
    """Make sure that the `TestClass` created above was rolled back."""
    assert not list(ghidra.getDataTypes("TestClass"))


def test_ghidra_forward_ref_to_pdb_type(type_importer: "PdbTypeImporter"):
    _set_up_test_class(type_importer.extraction.compare)
    imported_structure = type_importer.import_pdb_type_into_ghidra(forward_ref_key)
    _assert_test_class(imported_structure)


def test_forward_ref_to_missing_type(type_importer: "PdbTypeImporter"):
    type_importer.extraction.compare.types.keys[forward_ref_key] = CvdumpParsedType(
        type="LF_STRUCTURE",
        name="HWND__",
        field_list_type=CVInfoTypeEnum.T_NOTYPE,
        size=0,
        is_forward_ref=True,
    )

    with pytest.raises(
        TypeNotImplementedError,
        match="forward ref without target, needs to be created manually:",
    ):
        type_importer.import_pdb_type_into_ghidra(forward_ref_key)


def test_forward_ref_to_pre_existing_type(
    ghidra: "FlatProgramAPI", type_importer: "PdbTypeImporter"
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

    type_importer.extraction.compare.types.keys[forward_ref_key] = CvdumpParsedType(
        type="LF_STRUCTURE",
        name="HWND__",
        field_list_type=CVInfoTypeEnum.T_NOTYPE,
        size=0,
        is_forward_ref=True,
    )

    imported_hwnd = type_importer.import_pdb_type_into_ghidra(forward_ref_key)
    assert imported_hwnd == hwnd


def test_ghidra_pointer_to_class(type_importer: "PdbTypeImporter"):
    from ghidra.program.model.data import Pointer

    _set_up_test_class(type_importer.extraction.compare)
    imported_pointer = assert_instance(
        type_importer.import_pdb_type_into_ghidra(pointer_to_class_key), Pointer
    )
    _assert_test_class(imported_pointer.dataType)


def test_array(type_importer: "PdbTypeImporter"):
    from ghidra.program.model.data import Array

    array_key = CvdumpTypeKey.from_str("0x1005")
    type_importer.extraction.compare.types.keys[array_key] = CvdumpParsedType(
        type="LF_ARRAY", array_type=CVInfoTypeEnum.T_INT4, size=16
    )

    imported_array = assert_instance(
        type_importer.import_pdb_type_into_ghidra(array_key), Array
    )

    assert imported_array.getLength() == 16
    assert imported_array.getElementLength() == 4
    assert imported_array.getDataType() == type_importer.import_pdb_type_into_ghidra(
        CVInfoTypeEnum.T_INT4
    )


def test_enum(type_importer: "PdbTypeImporter"):
    from ghidra.program.model.data import Enum

    enum_fieldlist_key = CvdumpTypeKey.from_str("0x1006")
    enum_key = CvdumpTypeKey.from_str("0x1007")

    type_importer.extraction.compare.types.keys[enum_fieldlist_key] = CvdumpParsedType(
        type="LF_FIELDLIST",
        variants=[
            EnumItem(name="c_zero", value=0),
            EnumItem(name="c_one", value=1),
        ],
    )
    type_importer.extraction.compare.types.keys[enum_key] = CvdumpParsedType(
        name="TestEnum",
        type="LF_ENUM",
        field_list_type=enum_fieldlist_key,
        is_nested=False,
        num_members=2,
        underlying_type=CVInfoTypeEnum.T_INT4,
    )

    imported_enum = assert_instance(
        type_importer.import_pdb_type_into_ghidra(enum_key), Enum
    )
    assert imported_enum.getDisplayName() == "TestEnum"
    assert imported_enum.getCount() == 2
    assert list(imported_enum.getNames()) == ["c_zero", "c_one"]
    assert list(imported_enum.getValues()) == [0, 1]


def test_fallback_procedure_import(type_importer: "PdbTypeImporter"):
    """The feature is not fully implemented. This test asserts on the fallback behaviour."""

    arglist_key = CvdumpTypeKey.from_str("0x1008")
    procedure_key = CvdumpTypeKey.from_str("0x1009")
    _set_up_test_class(type_importer.extraction.compare)

    type_importer.extraction.compare.types.keys[arglist_key] = CvdumpParsedType(
        type="LF_ARGLIST", argcount=1, args=[pointer_to_class_key]
    )
    type_importer.extraction.compare.types.keys[procedure_key] = CvdumpParsedType(
        type="LF_PROCEDURE",
        return_type=CVInfoTypeEnum.T_VOID,
        call_type="C Near",
        func_attr="none",
        num_params=1,
        arg_list_type=arglist_key,
    )
    imported_type = type_importer.import_pdb_type_into_ghidra(procedure_key)
    # Fallback behaviour. This assertion should be changed if proper support is implemented
    assert imported_type == type_importer.import_pdb_type_into_ghidra(
        CVInfoTypeEnum.T_VOID
    )


@pytest.mark.xfail(reason="Union import not yet implemented")
def test_union(type_importer: "PdbTypeImporter"):
    from ghidra.program.model.data import Union

    union_field_list_key = CvdumpTypeKey.from_str("0x100a")
    union_key = CvdumpTypeKey.from_str("0x100b")

    type_importer.extraction.compare.types.keys[union_field_list_key] = (
        CvdumpParsedType(
            type="LF_FIELDLIST",
            members=[
                FieldListItem(offset=0, name="byte", type=CVInfoTypeEnum.T_32PUCHAR),
                FieldListItem(offset=0, name="word", type=CVInfoTypeEnum.T_32PUSHORT),
            ],
        )
    )
    type_importer.extraction.compare.types.keys[union_key] = CvdumpParsedType(
        type="LF_UNION",
        num_members=2,
        field_list_type=union_field_list_key,
        is_nested=True,
        size=4,
        name="MY_ENUM",
    )

    imported_union = assert_instance(
        type_importer.import_pdb_type_into_ghidra(union_key), Union
    )

    assert imported_union.getDisplayName() == "MY_ENUM"
    assert imported_union.getLength() == 4
    assert list(imported_union.getComponents()) == [
        type_importer.import_pdb_type_into_ghidra(CVInfoTypeEnum.T_32PUCHAR),
        type_importer.import_pdb_type_into_ghidra(CVInfoTypeEnum.T_32PUSHORT),
    ]


base_class_fieldlist_key = CvdumpTypeKey.from_str("0x100c")
base_class_key = CvdumpTypeKey.from_str("0x100d")
virtual_subclass_fieldlist_key = CvdumpTypeKey.from_str("0x100e")
virtual_subclass_key = CvdumpTypeKey.from_str("0x100f")
non_virtual_grandchild_fieldlist_key = CvdumpTypeKey.from_str("0x1010")
non_virtual_grandchild_key = CvdumpTypeKey.from_str("0x1011")


def _setup_virtual_inheritance_example(compare: Compare):
    compare.types.keys[base_class_fieldlist_key] = CvdumpParsedType(
        type="LF_FIELDLIST",
        members=[
            FieldListItem(offset=0, name="a", type=CVInfoTypeEnum.T_INT4),
        ],
    )
    compare.types.keys[base_class_key] = CvdumpParsedType(
        type="LF_CLASS",
        name="TestVirtualBaseClass",
        field_list_type=base_class_fieldlist_key,
        size=4,
    )

    # Memory layout:
    # 0x00: virtual function table
    # 0x04: virtual base pointer
    # 0x08: field "b"
    # 0x0c: space for virtual `TestVirtualBaseClass`
    #  +0x00: field "a"
    compare.types.keys[virtual_subclass_fieldlist_key] = CvdumpParsedType(
        type="LF_FIELDLIST",
        members=[
            FieldListItem(offset=0, type=CVInfoTypeEnum.T_32PVOID, name="vftable"),
            FieldListItem(offset=8, name="b", type=CVInfoTypeEnum.T_INT4),
        ],
        vbase=VirtualBasePointer(
            vboffset=4,
            bases=[VirtualBaseClass(type=base_class_key, index=1, direct=True)],
        ),
    )
    compare.types.keys[virtual_subclass_key] = CvdumpParsedType(
        type="LF_CLASS",
        name="TestVirtualSubClass",
        field_list_type=virtual_subclass_fieldlist_key,
        size=0x10,
    )

    # Memory layout:
    # 0x00: embedded  **slim** `TestVirtualSubClass` (without the TestVirtualBaseClass inside TestVirtualSubClass)
    #   +0x00: virtual function table
    #   +0x04: virtual base pointer
    #   +0x08: field "b"
    # 0x0c: field "c"
    # 0x10: space for virtual `TestVirtualBaseClass`
    #   +0x00: field "a"
    compare.types.keys[non_virtual_grandchild_fieldlist_key] = CvdumpParsedType(
        type="LF_FIELDLIST",
        super={virtual_subclass_key: 0},
        members=[FieldListItem(name="c", offset=0x0C, type=CVInfoTypeEnum.T_INT4)],
        vbase=VirtualBasePointer(
            vboffset=4,
            bases=[VirtualBaseClass(type=base_class_key, index=1, direct=False)],
        ),
    )
    compare.types.keys[non_virtual_grandchild_key] = CvdumpParsedType(
        type="LF_CLASS",
        name="TestNonVirtualGrandchildClass",
        field_list_type=non_virtual_grandchild_fieldlist_key,
        size=0x14,
    )


def test_virtual_base_ptr(type_importer: "PdbTypeImporter"):
    from ghidra.program.model.data import (
        Structure,
        Pointer,
        TypeDef,
        ComponentOffsetSettingsDefinition,
    )

    _setup_virtual_inheritance_example(type_importer.extraction.compare)

    # Part 1: Assert on the layout of the class

    virtual_subclass = assert_instance(
        type_importer.import_pdb_type_into_ghidra(virtual_subclass_key), Structure
    )

    [vftable_component, vbaseptr_component, b_field_component, *unallocated] = list(
        virtual_subclass.getComponents()
    )
    assert vftable_component.getFieldName() == "vftable"

    assert vbaseptr_component.getFieldName() == "vbase_offset"
    vbase_record_ptr = assert_instance(vbaseptr_component.getDataType(), Pointer)

    assert b_field_component.getFieldName() == "b"
    # Unallocated bytes from 0x0c to 0x0f because we currently don't parse the virtual layout.
    # It requires looking into the recompiled binary and finding the actual virtual base tables.
    # Strictly speaking, they don't even have to be uniform for one type (e.g. across multiple constructors).
    assert len(unallocated) == 4
    for i, value in enumerate(unallocated):
        assert value.getOffset() == 0x0C + i
        assert value.getDataType().getName() == "undefined"

    # Part 2: Assert on the virtual base pointer type

    vbase_record = assert_instance(vbase_record_ptr.getDataType(), Structure)
    [vbase_self_component, vbase_base_component] = list(vbase_record.getComponents())

    assert vbase_self_component.getFieldName() == "o_self"
    vbase_self_ptr = assert_instance(vbase_self_component.getDataType(), Pointer)
    assert vbase_self_ptr.getDataType() == virtual_subclass

    assert vbase_base_component.getFieldName() == "o_TestVirtualBaseClass"

    vbase_base_ptr_typedef = assert_instance(
        vbase_base_component.getDataType(), TypeDef
    )
    assert (
        ComponentOffsetSettingsDefinition.DEF.getValue(
            vbase_base_ptr_typedef.getDefaultSettings()
        )
        == -4
    )

    vbase_base_ptr = assert_instance(vbase_base_ptr_typedef.getDataType(), Pointer)
    imported_base_class = assert_instance(vbase_base_ptr.getDataType(), Structure)
    assert imported_base_class.getName() == "TestVirtualBaseClass"


def test_slim_vbase_pointer(type_importer: "PdbTypeImporter"):
    from ghidra.program.model.data import Structure

    _setup_virtual_inheritance_example(type_importer.extraction.compare)
    non_virtual_grandchild = assert_instance(
        type_importer.import_pdb_type_into_ghidra(non_virtual_grandchild_key), Structure
    )

    [base_component, c_field_component, *unallocated] = list(
        non_virtual_grandchild.getComponents()
    )

    assert base_component.getFieldName() == "base"
    virtual_child_slim = assert_instance(base_component.getDataType(), Structure)
    assert virtual_child_slim.getName() == "TestVirtualSubClass_vbase_slim"
    # The full size of `TestVirtualSubClass` is 0x10, the slim size is 0x0c
    assert virtual_child_slim.getLength() == 0x0C

    assert c_field_component.getFieldName() == "c"
    assert c_field_component.getOffset() == 0x0C
    assert c_field_component.getDataType().getLength() == 4

    # Unallocated bytes from 0x10 to 0x13 because we currently don't parse the virtual layout.
    # It requires looking into the recompiled binary and finding the actual virtual base tables.
    # Strictly speaking, they don't even have to be uniform for one type (e.g. across multiple constructors).
    assert len(unallocated) == 4
    for i, value in enumerate(unallocated):
        assert value.getOffset() == 0x10 + i
        assert value.getDataType().getName() == "undefined"
