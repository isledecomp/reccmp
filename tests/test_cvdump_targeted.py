from pathlib import Path
from unittest.mock import patch

from reccmp.cvdump import Cvdump
from reccmp.cvdump.parser import CvdumpParser
from reccmp.cvdump.targeted import SymbolModuleHint, select_modules
from tests.raw_image import RawImage

MODULES = r"""
0007 "CMakeFiles/App.dir/src/foo.cpp.obj"
01E6 "CMakeFiles/App.dir/src/CObject.cpp.obj"
01F5 "CMakeFiles/App.dir/src/ArchiveStreamAdapter.cpp.obj"
"""

GLOBALS = "S_PROCREF: 0x00000000: ( 501, 00000840) CObject::Serialize"

PUBLICS = "S_PUB32: [0001:00000030], Flags: 00000000, ?Named@@YAXXZ"

CONTRIBUTIONS = """
  0007  0001:00000100  00000040  60501020
  01F5  0001:00000030  00000003  60501020
"""


def sample_parser() -> CvdumpParser:
    parser = CvdumpParser()
    parser.read_section("MODULES", MODULES)
    parser.read_section("GLOBALS", GLOBALS)
    parser.read_section("PUBLICS", PUBLICS)
    parser.read_section("SECTION CONTRIBUTIONS", CONTRIBUTIONS)
    return parser


def test_line_annotation_selects_matching_source_module():
    selection = select_modules(
        sample_parser(),
        RawImage.from_memory(),
        [SymbolModuleHint(Path("/repo/src/foo.cpp"))],
        [],
    )

    assert selection.module_ids == frozenset({7})
    assert not selection.requires_full_symbols


def test_name_annotation_uses_proc_ref_module_not_source_module():
    selection = select_modules(
        sample_parser(),
        RawImage.from_memory(),
        [
            SymbolModuleHint(
                Path("/repo/src/CObject.cpp"), lookup_name="CObject::Serialize"
            )
        ],
        [],
    )

    assert selection.module_ids == frozenset({501})


def test_decorated_name_uses_public_section_contribution():
    selection = select_modules(
        sample_parser(),
        RawImage.from_memory(),
        [SymbolModuleHint(Path("unused.cpp"), lookup_name="?Named@@YAXXZ")],
        [],
    )

    assert selection.module_ids == frozenset({501})


def test_unresolved_known_annotation_requires_full_symbols():
    selection = select_modules(
        sample_parser(),
        RawImage.from_memory(),
        [SymbolModuleHint(Path("missing.cpp"), lookup_name="Missing")],
        [],
    )

    assert selection.requires_full_symbols


def test_cvdump_module_filter_is_decimal():
    with patch(
        "reccmp.cvdump.runner._wine_cvdump_path", return_value=r"Z:\build\App.pdb"
    ):
        command = Cvdump("App.pdb").symbols().module(501).cmd_line()

    assert "-M501" in command
