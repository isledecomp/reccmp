import pytest
from reccmp.types import EntityType
from reccmp.cvdump.parser import CvdumpParser
from reccmp.cvdump.symbols import SymbolsEntry
from reccmp.cvdump.analysis import (
    CvdumpAnalysis,
    CvdumpNode,
)
from reccmp.cvdump.cvinfo import CvdumpTypeKey as TK

TEST_SYMBOLS = [
    SymbolsEntry(
        type="S_GPROC32",
        section=1,
        offset=0xCC3,
        size=0xA9,
        func_type=TK(0x100D),
        name="__setargv",
    ),
    SymbolsEntry(
        type="S_LPROC32",
        section=1,
        offset=0x12EC,
        size=0x56,
        func_type=TK(0x100D),
        name="check_managed_app",
    ),
]


def test_cvdump_analysis_functions():
    parser = CvdumpParser()
    parser.symbols_parser.symbols = TEST_SYMBOLS
    analysis = CvdumpAnalysis(parser)

    expected = [
        CvdumpNode(
            node_type=EntityType.FUNCTION,
            section=1,
            offset=0xCC3,
            confirmed_size=0xA9,
            symbol_entry=TEST_SYMBOLS[0],
            friendly_name="__setargv",
            estimated_size=1577,
        ),
        CvdumpNode(
            node_type=EntityType.FUNCTION,
            section=1,
            offset=0x12EC,
            confirmed_size=0x56,
            symbol_entry=TEST_SYMBOLS[1],
            friendly_name="check_managed_app",
        ),
    ]

    assert analysis.nodes == expected


@pytest.mark.parametrize(
    "name",
    (
        "__TI3?AVlength_error@std@@",
        "__CTA3?AVlength_error@std@@",
        "__CT??_R0?AVlength_error@std@@@8??0length_error@std@@QAE@ABV01@@Z12",
        "__TI1H",
        "__CTA1H",
        "__CT??_R0H@84",
        "__TI2PAD",
        "__CTA2PAD",
        "__CT??_R0PAD@84",
        "__CT??_R0PAX@84",
    ),
)
def test_eh_records_are_not_functions(name: str):
    """The compiler's C++ exception-handling records carry a C-looking name,
    some even ending in what looks like a parameter byte count. Leaving them
    untyped lets match_variables pair them with a GLOBAL annotation."""
    node = CvdumpNode(section=2, offset=0)
    node.set_decorated(name)
    assert node.node_type is None


@pytest.mark.parametrize(
    "name",
    (
        "_DirectSoundCreate@12",  # __stdcall
        "@Foo@8",  # __fastcall
        "Foo@@8",  # __vectorcall
    ),
)
def test_c_mangled_name_is_function(name: str):
    node = CvdumpNode(section=1, offset=0)
    node.set_decorated(name)
    assert node.node_type == EntityType.FUNCTION
