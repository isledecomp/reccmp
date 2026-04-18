# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

import json
from typing import TYPE_CHECKING, Iterator

import pytest
from reccmp.compare.ingest import load_cvdump_types
from reccmp.cvdump.analysis import CvdumpAnalysis
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey
from reccmp.compare.db import ReccmpMatch

from reccmp.cvdump.parser import CvdumpParser
from reccmp.ghidra.importer.pdb_extraction import (
    CppRegisterSymbol,
    CppStackSymbol,
    FunctionSignature,
)

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter


ORIG_FN_TO_OVERWRITE_PRIMARY = 0x00402880  # readIntFromRegistry()
ORIG_FN_TO_OVERWRITE_SECONDARY = 0x00402C20  # IsleApp::Tick()


class GhidraFunctionTestHelper:
    def __init__(self, ghidra: "FlatProgramAPI"):
        self.ghidra = ghidra
        self.orig_address = ORIG_FN_TO_OVERWRITE_PRIMARY
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
) -> Iterator[GhidraFunctionTestHelper]:
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

    # Shortened version of a BETA10 recompilation
    cvdump_types = """
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

0x6080 : Length = 62, Leaf = 0x1203 LF_FIELDLIST
	list[1] = LF_MEMBER, public, type = T_32PRCHAR(0470), offset = 0
		member name = 'm_name'
	list[2] = LF_MEMBER, public, type = T_ULONG(0022), offset = 4
		member name = 'm_type'

0x6081 : Length = 42, Leaf = 0x1505 LF_STRUCTURE
	# members = 3,  field list type 0x6080,
	Derivation list type 0x0000, VT shape type 0x0000
	Size = 8, class name = LegoAnimActorEntry, UDT(0x00006081)
    """

    legoanim_class_key = CvdumpTypeKey(0x12CF)

    compare = type_importer.extraction.compare

    parser = CvdumpParser()
    parser.read_section("TYPES", cvdump_types)
    analysis = CvdumpAnalysis(parser)
    load_cvdump_types(analysis, compare.types)

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
        class_type=legoanim_class_key,
        stack_symbols=[
            CppRegisterSymbol("this", legoanim_class_key, "ecx"),
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
