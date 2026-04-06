# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

import json
from typing import TYPE_CHECKING, Generator
from unittest.mock import Mock

import pytest
from reccmp.compare.core import Compare
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey
from reccmp.compare.db import ReccmpMatch

from reccmp.cvdump.types import CvdumpParsedType, FieldListItem
from reccmp.ghidra.importer.pdb_extraction import (
    CppRegisterSymbol,
    CppStackSymbol,
    FunctionSignature,
    PdbFunctionExtractor,
)
from tests.test_image_raw import RawImage

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter


class_field_list_key = CvdumpTypeKey.from_str("0x1002")
class_key = CvdumpTypeKey.from_str("0x1003")
anim_actor_entry_key = CvdumpTypeKey.from_str("0x1004")
anim_actor_entry_pointer_key = CvdumpTypeKey.from_str("0x1005")
anim_actor_entry_field_list_key = CvdumpTypeKey.from_str("0x1006")


# TODO: Fix code duplication with other Ghidra test file
@pytest.fixture(name="type_importer", scope="function")
def pdb_type_importer_fixture(ghidra: "FlatProgramAPI") -> "Generator[PdbTypeImporter]":
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter

    compare = Compare(RawImage.from_memory(), RawImage.from_memory(), Mock(), "TEST")
    type_importer = PdbTypeImporter(ghidra, PdbFunctionExtractor(compare), set())
    yield type_importer


class GhidraFunctionTestHelper:
    def __init__(self, ghidra: "FlatProgramAPI"):
        self.ghidra = ghidra
        self.orig_address = 0x00402880  # readIntFromRegistry()
        self.address_ghidra = ghidra.getAddressFactory().getAddress(
            hex(self.orig_address)
        )
        self.ghidra_function = self.ghidra.getFunctionContaining(self.address_ghidra)
        assert (
            self.ghidra_function is not None
        ), f"No Ghidra function at address {self.address_ghidra}"

    def overwrite_example_function(self, data: bytes):
        from jpype import JArray, JByte  # type: ignore[import-untyped]

        assert len(data) > 0

        # Clear the existing decompiled code so we can overwrite it
        listing = self.ghidra.getCurrentProgram().getListing()
        end_addr = self.address_ghidra.add(len(data) - 1)
        listing.clearCodeUnits(self.address_ghidra, end_addr, False)

        # Overwrite the memory
        self.ghidra.getCurrentProgram().getMemory().setBytes(
            self.address_ghidra, JArray.of(data, JByte)
        )

    def assert_c_code(self, code: str):
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import TaskMonitor

        iface = DecompInterface()
        iface.openProgram(self.ghidra.getCurrentProgram())

        res = iface.decompileFunction(self.ghidra_function, 5, TaskMonitor.DUMMY)
        assert res.decompileCompleted(), "Decompilation failed"

        # The line endings returned by the API differ between Windows and Linux
        decompiled_c_code = res.getDecompiledFunction().getC().replace("\r\n", "\n")

        # This print statement is suppressed when the test passes, but is helpful if the test fails
        print(decompiled_c_code)

        assert decompiled_c_code == code


@pytest.fixture(name="function_helper", scope="function")
def ghidra_function_helper_fixture(
    ghidra: "FlatProgramAPI",
) -> Generator[GhidraFunctionTestHelper]:
    yield GhidraFunctionTestHelper(ghidra)


def test_import_trivial_function(
    ghidra: "FlatProgramAPI",
    function_helper: GhidraFunctionTestHelper,
    type_importer: "PdbTypeImporter",
):
    from reccmp.ghidra.importer.function_importer import (
        PdbFunctionImporter,
        PdbFunction,
    )

    function_helper.overwrite_example_function(b"\xc3")

    func_signature = FunctionSignature(
        call_type="__stdcall",
        arglist=[],
        return_type=CVInfoTypeEnum.T_VOID,
        class_type=None,
        stack_symbols=[],
        this_adjust=0,
    )
    pdb_function = PdbFunction(
        ReccmpMatch(
            function_helper.orig_address, 1234, json.dumps({"name": "MyTestFn"})
        ),
        func_signature,
        is_stub=False,
    )

    PdbFunctionImporter.build(
        ghidra, pdb_function, type_importer, []
    ).overwrite_ghidra_function(function_helper.ghidra_function)

    function_helper.assert_c_code("""
void MyTestFn(void)

{
  return;
}

""")


def test_record_array_access(
    ghidra: "FlatProgramAPI",
    function_helper: GhidraFunctionTestHelper,
    type_importer: "PdbTypeImporter",
):
    from reccmp.ghidra.importer.function_importer import (
        PdbFunctionImporter,
        PdbFunction,
    )

    compare = type_importer.extraction.compare
    # LegoAnimActorEntry
    compare.types.keys[anim_actor_entry_field_list_key] = CvdumpParsedType(
        type="LF_FIELDLIST",
        members=[
            FieldListItem(offset=0, name="m_name", type=CVInfoTypeEnum.T_32PCHAR),
            FieldListItem(offset=4, name="m_type", type=CVInfoTypeEnum.T_INT4),
        ],
    )
    compare.types.keys[anim_actor_entry_key] = CvdumpParsedType(
        type="LF_CLASS",
        name="LegoAnimActorEntry",
        field_list_type=anim_actor_entry_field_list_key,
        size=8,
    )
    compare.types.keys[anim_actor_entry_pointer_key] = CvdumpParsedType(
        type="LF_POINTER", element_type=anim_actor_entry_key
    )
    # LegoAnim (shortened)
    compare.types.keys[class_field_list_key] = CvdumpParsedType(
        type="LF_FIELDLIST",
        members=[
            FieldListItem(offset=0, name="id", type=CVInfoTypeEnum.T_INT4),
            FieldListItem(offset=4, name="name", type=CVInfoTypeEnum.T_32PCHAR),
            FieldListItem(
                offset=0xC, name="m_modelList", type=anim_actor_entry_pointer_key
            ),
        ],
    )
    compare.types.keys[class_key] = CvdumpParsedType(
        type="LF_CLASS",
        name="LegoAnim",
        field_list_type=class_field_list_key,
        size=0x10,
    )

    # shortened version of LEGO1 0x100a0f20
    function_helper.overwrite_example_function(
        b"\x8b\x54\x24\x04"  # MOV EDX, dword ptr [ESP + p_index]
        b"\x8b\x41\x0c"  # MOV EAX, dword ptr [ECX + this->m_modelList]
        b"\x8b\x04\xd0"  # MOV EAX, dword ptr [EAX + EDX*0x8]
        b"\xc2\x04\x00"  # RET 0x4
    )

    func_signature = FunctionSignature(
        call_type="__thiscall",
        arglist=[CVInfoTypeEnum.T_INT4],
        return_type=CVInfoTypeEnum.T_32PCHAR,
        class_type=class_key,
        stack_symbols=[
            CppRegisterSymbol("this", class_key, "ecx"),
            CppStackSymbol("p_index", CVInfoTypeEnum.T_INT4, 4),
        ],
        this_adjust=0,
    )
    pdb_function = PdbFunction(
        ReccmpMatch(
            function_helper.orig_address,
            1234,
            json.dumps({"name": "LegoAnim::GetActorName"}),
        ),
        func_signature,
        is_stub=False,
    )

    PdbFunctionImporter.build(
        ghidra, pdb_function, type_importer, []
    ).overwrite_ghidra_function(function_helper.ghidra_function)

    function_helper.assert_c_code("""
char * __thiscall LegoAnim::GetActorName(LegoAnim *this,int p_index)

{
  return this->m_modelList[p_index].m_name;
}

""")
