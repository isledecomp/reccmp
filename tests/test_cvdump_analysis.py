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

    def test_node(node: CvdumpNode, sym: SymbolsEntry):
        return (
            node.section == sym.section
            and node.offset == sym.offset
            and node.friendly_name == sym.name
            and node.confirmed_size == sym.size
            and node.node_type == EntityType.FUNCTION
            and node.symbol_entry == sym
        )

    analysis = CvdumpAnalysis(parser)
    assert len(analysis.nodes) == len(TEST_SYMBOLS)
    assert all(map(test_node, analysis.nodes, TEST_SYMBOLS))
