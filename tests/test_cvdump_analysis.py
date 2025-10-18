from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.cvdump.parser import CvdumpParser
from reccmp.isledecomp.cvdump.symbols import SymbolsEntry
from reccmp.isledecomp.cvdump.analysis import (
    CvdumpAnalysis,
    CvdumpNode,
)


TEST_SYMBOLS = [
    SymbolsEntry(
        type="S_GPROC32",
        section=1,
        offset=0xCC3,
        size=0xA9,
        func_type="0x100D",
        name="__setargv",
    ),
    SymbolsEntry(
        type="S_LPROC32",
        section=1,
        offset=0x12EC,
        size=0x56,
        func_type="0x100D",
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
