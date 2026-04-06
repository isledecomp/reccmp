# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

import json
from typing import TYPE_CHECKING, Generator
from unittest.mock import Mock

import pytest
from reccmp.compare.core import Compare
from reccmp.cvdump.cvinfo import CVInfoTypeEnum
from reccmp.compare.db import ReccmpMatch  # todo move global

from reccmp.ghidra.importer.pdb_extraction import (
    FunctionSignature,
    PdbFunctionExtractor,
)
from tests.test_image_raw import RawImage

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter


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
        self.address_ghidra = ghidra.getAddressFactory().getAddress(hex(self.orig_address))
        self.ghidra_function = self.ghidra.getFunctionContaining(self.address_ghidra)
        assert self.ghidra_function is not None, f"No Ghidra function at address {self.address_ghidra}"

    def overwrite_example_function(self, data: bytes):
        from jpype import JArray, JByte  # type: ignore[import-untyped]
        assert len(data) > 0

        # Clear the existing decompiled code so we can overwrite it
        listing = self.ghidra.getCurrentProgram().getListing()
        end_addr = self.address_ghidra.add(len(data) - 1)
        listing.clearCodeUnits(self.address_ghidra, end_addr, False)

        # Overwrite the memory
        self.ghidra.getCurrentProgram().getMemory().setBytes(self.address_ghidra, JArray.of(data, JByte))

    def assert_c_code(self, code: str):
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import TaskMonitor
        iface = DecompInterface()
        iface.openProgram(self.ghidra.getCurrentProgram())

        res = iface.decompileFunction(self.ghidra_function, 5, TaskMonitor.DUMMY)
        assert res.decompileCompleted(), "Decompilation failed"

        # The line endings returned by the API differ between Windows and Linux
        decompiled_c_code = res.getDecompiledFunction().getC().replace("\r\n", "\n")

        assert decompiled_c_code == code


@pytest.fixture(name="function_helper", scope="function")
def ghidra_function_helper_fixture(ghidra: "FlatProgramAPI") -> Generator[GhidraFunctionTestHelper]:
    yield GhidraFunctionTestHelper(ghidra)


def test_import_trivial_function(ghidra: "FlatProgramAPI", function_helper: GhidraFunctionTestHelper, type_importer: "PdbTypeImporter"):
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
        ReccmpMatch(function_helper.orig_address, 1234, json.dumps({"name": "MyTestFn"})),
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

"""
    )
