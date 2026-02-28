# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

from unittest.mock import Mock

import pytest
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeMap

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
