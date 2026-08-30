# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

from typing import TYPE_CHECKING

import pytest
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey, CvdumpTypeMap
from reccmp.ghidra.importer.exceptions import TypeNotFoundError, TypeNotImplementedError
from .cvdump_sample import CvdumpSample, load_cvdump_sample
from .ghidra_integration_test_setup import GhidraTypeTestHelper
from .helpers import assert_instance

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import DataType


@pytest.fixture(name="cvdump_sample", scope="module")
def cvdump_sample_fixture():
    """Shortened version of a BETA10 recompilation"""
    return load_cvdump_sample("ghidra-integration-type-imports")


def _assert_legoanimactorentry(imported_structure: "DataType"):
    """Helper to assert the contents of the `LegoAnimActorEntry` struct
    used in multiple tests."""
    from ghidra.program.model.data import Structure

    assert isinstance(imported_structure, Structure)

    assert imported_structure.getDisplayName() == "LegoAnimActorEntry"
    assert imported_structure.length == 8

    [name_component, id_component] = list(imported_structure.getComponents())
    assert name_component.getOffset() == 0
    assert name_component.getDataType().name == "char *"
    assert id_component.getOffset() == 4
    assert id_component.getDataType().name == "ulong"


verified_types = tuple(
    t
    for t in CVInfoTypeEnum
    if CvdumpTypeMap[t].verified and t != CVInfoTypeEnum.T_NOTYPE
)


@pytest.mark.parametrize("scalar_type", verified_types)
def test_ghidra_scalar_types(
    type_helper: GhidraTypeTestHelper, scalar_type: CVInfoTypeEnum
):
    """Importing primitive (scalar) types.
    The type database should resolve these without reading any sample data."""
    from ghidra.program.model.data import Pointer

    cv_type_info = CvdumpTypeMap[scalar_type]

    ghidra_type = type_helper.type_importer.import_pdb_type_into_ghidra(scalar_type)
    assert ghidra_type.length == cv_type_info.size

    # Make sure primitive pointer types are recognized as such.
    if cv_type_info.pointer is not None:
        assert isinstance(ghidra_type, Pointer)

    # Repeating the import does not create a duplicate type in Ghidra's database.
    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(scalar_type)
    assert second_import == ghidra_type


def test_ghidra_type_not_found(type_helper: GhidraTypeTestHelper):
    """Should raise `TypeNotFoundError` if the type key does not exist in our type database."""
    with pytest.raises(TypeNotFoundError, match="Failed to find referenced type"):
        type_helper.type_importer.import_pdb_type_into_ghidra(CvdumpTypeKey(0x1001))


def test_ghidra_type_class(
    type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample
):
    """Importing `LegoAnimActorEntry`, a struct with no virtual functions."""
    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("legoanimactor-class-key")

    imported_structure = type_helper.type_importer.import_pdb_type_into_ghidra(key)

    # Make sure the imported type matches the expected struct.
    _assert_legoanimactorentry(imported_structure)

    # Repeating the import does not create a duplicate type in Ghidra's database.
    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    assert second_import == imported_structure


def test_ghidra_verify_test_isolation(ghidra: "FlatProgramAPI"):
    """Make sure that the `LegoAnimActorEntry` created above was rolled back."""
    assert not list(ghidra.getDataTypes("LegoAnimActorEntry"))


def test_ghidra_forward_ref_to_pdb_type(
    type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample
):
    """Importing a cvdump leaf with a forward reference to another leaf in the text."""
    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("legoanimactor-forward-ref-key")

    imported_structure = type_helper.type_importer.import_pdb_type_into_ghidra(key)

    # Make sure the imported type matches the expected struct.
    _assert_legoanimactorentry(imported_structure)

    # Repeating the import does not create a duplicate type in Ghidra's database.
    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    assert second_import == imported_structure


def test_forward_ref_to_missing_type(
    type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample
):
    """Importing a cvdump leaf with a forward reference that is unresolved in the text.
    We have seen this with `HWND__` in real data, so we use that in the example.
    In this case, `HWND__` does not already exist, so it is impossible to complete the import.
    """
    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("hwnd-key")

    with pytest.raises(
        TypeNotImplementedError,
        match="forward ref without target, needs to be created manually:",
    ):
        type_helper.type_importer.import_pdb_type_into_ghidra(key)


def test_forward_ref_to_pre_existing_type(
    ghidra: "FlatProgramAPI",
    type_helper: GhidraTypeTestHelper,
    cvdump_sample: CvdumpSample,
):
    """Importing a cvdump leaf with a forward reference that is unresolved in the text.
    We have seen this with `HWND__` in real data, so we use that in the example.
    In this case, we create `HWND__` manually so the forward reference can be completed.
    """
    data_type_manager = ghidra.getCurrentProgram().getDataTypeManager()
    from ghidra.program.model.data import (
        TypedefDataType,
        VoidDataType,
        DataTypeConflictHandler,
    )

    # Make sure `HWND__` exists in Ghidra before importing the cvdump type.
    hwnd = data_type_manager.addDataType(
        TypedefDataType("HWND__", VoidDataType()), DataTypeConflictHandler.KEEP_HANDLER
    )

    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("hwnd-key")

    # The type imported by the forward reference should match the type we created manually.
    imported_hwnd = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    assert imported_hwnd == hwnd


def test_ghidra_pointer_to_class(
    type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample
):
    """Importing `LegoAnimActorEntry*`, which also creates `LegoAnimActorEntry`."""
    from ghidra.program.model.data import Pointer

    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("legoanimactor-pointer-key")

    # Ghidra recognized it as a pointer.
    imported_pointer = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(key),
        Pointer,
    )

    # The struct was also imported and our pointer points at it.
    _assert_legoanimactorentry(imported_pointer.dataType)

    # Repeating the import does not create a duplicate type in Ghidra's database.
    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    assert second_import == imported_pointer


def test_pointer_to_scalar(
    type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample
):
    """Importing `const char*` from an LF_POINTER leaf.
    Ghidra has no concept of `const` so this should resolve to `char*`."""
    from ghidra.program.model.data import Pointer

    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("pointer-to-char-key")

    # Ghidra recognized it as a pointer.
    imported_pointer = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(key),
        Pointer,
    )

    # Ghidra recognized it as a `char*` pointer.
    assert (
        imported_pointer.dataType
        == type_helper.type_importer.import_pdb_type_into_ghidra(CVInfoTypeEnum.T_CHAR)
    )

    # Repeating the import does not create a duplicate type in Ghidra's database.
    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    assert second_import == imported_pointer


def test_array(type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample):
    """Importing `unsigned long[4]` array."""
    from ghidra.program.model.data import Array

    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("array-key")

    # Ghidra recognized it as an pointer.
    imported_array = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(key), Array
    )

    # The array length, total size, and element type were all set properly.
    assert imported_array.getLength() == 16
    assert imported_array.getElementLength() == 4
    assert (
        imported_array.getDataType()
        == type_helper.type_importer.import_pdb_type_into_ghidra(CVInfoTypeEnum.T_ULONG)
    )

    # Repeating the import does not create a duplicate type in Ghidra's database.
    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    assert second_import == imported_array


def test_enum(type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample):
    """Importing an `int` enum type."""
    from ghidra.program.model.data import Enum

    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("enum-key")

    # Ghidra recognized it as an enum.
    imported_enum = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(key), Enum
    )

    # The names and (non-contiguous) values of the enum were all imported correctly.
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

    # Repeating the import does not create a duplicate type in Ghidra's database.
    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    assert second_import == imported_enum


def test_enum_with_negative_value(
    type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample
):
    """Importing an `int` enum with a number that resolves to a negative number."""
    from ghidra.program.model.data import Enum

    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("enum-with-negative-value-key")

    # Ghidra recognized it as an enum.
    imported_enum = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(key),
        Enum,
    )

    # The names and (non-contiguous) values of the enum were all imported correctly.
    assert imported_enum.getDisplayName() == "Unknown0xf8"
    assert imported_enum.getCount() == 2
    assert list(imported_enum.getNames()) == ["c_unknownminusone", "c_unknown8"]
    assert list(imported_enum.getValues()) == [-1, 8]

    # Repeating the import does not create a duplicate type in Ghidra's database.
    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    assert second_import == imported_enum


def test_fallback_procedure_import(
    type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample
):
    """The feature is not fully implemented. This test asserts on the fallback behaviour."""

    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("procedure-key")

    imported_type = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    # Fallback behaviour. This assertion should be changed if proper support is implemented
    assert imported_type == type_helper.type_importer.import_pdb_type_into_ghidra(
        CVInfoTypeEnum.T_VOID
    )

    # Repeating the import does not create a duplicate type in Ghidra's database.
    second_import = type_helper.type_importer.import_pdb_type_into_ghidra(key)
    assert second_import == imported_type


@pytest.mark.xfail(reason="Union import not yet implemented")
def test_union(type_helper: GhidraTypeTestHelper, cvdump_sample: CvdumpSample):
    from ghidra.program.model.data import Union

    type_helper.set_up_cvdump_types(cvdump_sample.text)
    key = cvdump_sample.key("union-key")

    _imported_union = assert_instance(
        type_helper.type_importer.import_pdb_type_into_ghidra(key), Union
    )

    # More assertions are needed once we have proper support
