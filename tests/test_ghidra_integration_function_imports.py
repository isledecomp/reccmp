# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

import json
from typing import TYPE_CHECKING

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
from .ghidra_integration_test_setup import (
    GhidraFunctionTestHelper,
    GhidraTypeTestHelper,
)

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI


def test_import_trivial_function(
    ghidra: "FlatProgramAPI",
    function_helper: GhidraFunctionTestHelper,
    type_helper: GhidraTypeTestHelper,
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
        ghidra, pdb_function, type_helper.type_importer, []
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
    type_helper: GhidraTypeTestHelper,
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

    compare = type_helper.type_importer.extraction.compare

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
        ghidra, pdb_function, type_helper.type_importer, []
    ).overwrite_ghidra_function(function_helper.ghidra_function)

    function_helper.assert_c_code("""
char * __thiscall LegoAnim::GetActorName(LegoAnim *this,int p_index)

{
  return this->m_modelList[p_index].m_name;
}

""")
