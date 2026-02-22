# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

from unittest.mock import Mock
from reccmp.cvdump.cvinfo import CVInfoTypeEnum


def test_ghidra_experiment(ghidra):
    from reccmp.ghidra.importer.type_importer import PdbTypeImporter

    type_importer = PdbTypeImporter(ghidra, Mock(), set())
    int4 = type_importer.import_pdb_type_into_ghidra(CVInfoTypeEnum.T_INT4)
    assert int4.length == 4
