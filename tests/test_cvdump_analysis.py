from textwrap import dedent
import pytest
from reccmp.formats import PEImage
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


def test_cvdump_analysis_functions(binfile: PEImage):
    parser = CvdumpParser()
    parser.symbols_parser.symbols = TEST_SYMBOLS
    analysis = CvdumpAnalysis(parser, binfile)

    expected = [
        CvdumpNode(
            node_type=EntityType.FUNCTION,
            section=1,
            offset=0xCC3,
            addr=0x10001CC3,
            confirmed_size=0xA9,
            symbol_entry=TEST_SYMBOLS[0],
            friendly_name="__setargv",
            estimated_size=1577,
        ),
        CvdumpNode(
            node_type=EntityType.FUNCTION,
            section=1,
            offset=0x12EC,
            addr=0x100022EC,
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
    node = CvdumpNode(section=2, offset=0, addr=0)
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
    node = CvdumpNode(section=1, offset=0, addr=0)
    node.set_decorated(name)
    assert node.node_type == EntityType.FUNCTION


def get_node(analysis: CvdumpAnalysis, addr: int) -> CvdumpNode:
    (node,) = [n for n in analysis.nodes if n.addr == addr]
    return node


def test_static_var_in_proc(binfile: PEImage):
    """An S_LDATA32 leaf inside a procedure block denotes a static variable for that function."""
    parser = CvdumpParser()
    parser.read_section(
        "SYMBOLS",
        dedent(
            """        (001930) S_GPROC32: [0001:0003EF00], Cb: 00000129, Type:             0x1E4E, KevKeyService
                 Parent: 00000000, End: 00001A10, Next: 00000000
                 Debug start: 00000000, Debug end: 00000121

        (001968)  S_LDATA32: [0003:0000A2B0], Type:      T_UINT4(0075), last_single_key
        (001988)  S_LDATA32: [0003:0003D908], Type:             0x1F00, return_val
        (0019A4)  S_LDATA32: [0003:0003D8FC], Type:      T_UINT4(0075), code
        (0019B8)  S_LDATA32: [0003:0003D8F8], Type:      T_UINT4(0075), last_time
        (0019D0)  S_LDATA32: [0003:0003D910], Type:      T_UINT4(0075), code2
        (0019E4)  S_LDATA32: [0003:0000A2AC], Type:      T_UINT4(0075), last_key
        (0019FC)  S_LDATA32: [0003:0003D900], Type:      T_UINT4(0075), sum

        (001A10) S_END
        """
        ),
    )
    analysis = CvdumpAnalysis(parser, binfile)

    node = get_node(analysis, binfile.get_abs_addr(3, 0x3D908))
    assert node.node_type == EntityType.DATA
    assert node.friendly_name == "return_val"
    assert node.static_var is True
    assert node.parent_function == binfile.get_abs_addr(1, 0x3EF00)


def test_static_var_in_publics(binfile: PEImage):
    """Should detect the function for a static variable if we have public symbols for both.
    The function symbol is a substring of the variable symbol in this example."""
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        dedent(
            """        S_PUB32: [0001:00001C20], Flags: 00000002, ?Tick@IsleApp@@QAEXH@Z
        S_PUB32: [0003:00000010], Flags: 00000000, ?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA
        """
        ),
    )
    analysis = CvdumpAnalysis(parser, binfile)

    node = get_node(analysis, binfile.get_abs_addr(3, 0x10))
    assert node.node_type == EntityType.DATA
    assert node.friendly_name == "g_startupDelay"
    assert node.static_var is True
    assert node.parent_function == binfile.get_abs_addr(1, 0x1C20)


def test_static_var_in_publics_back_references(binfile: PEImage):
    """Should detect the function for a static variable even if the mangled names
    use back-references. This will cause the function symbol to not be a substring of
    the variable symbol. We demangle everything to work around this problem."""
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        dedent(
            """        S_PUB32: [0001:00001C20], Flags: 00000002, ?BackRefs@@YAXPAUA@ns@@PAUB@2@PAUC@2@PAUD@2@03@Z
        S_PUB32: [0003:00000010], Flags: 00000000, ?s_backref@?1??BackRefs@@YAXPAUA@ns@@PAUB@3@PAUC@3@PAUD@3@03@Z@4HA
        """
        ),
    )
    analysis = CvdumpAnalysis(parser, binfile)

    node = get_node(analysis, binfile.get_abs_addr(3, 0x10))
    assert node.static_var is True
    assert node.parent_function == binfile.get_abs_addr(1, 0x1C20)


def test_static_var_in_publics_no_parent(binfile: PEImage):
    """For a static variable detected by public symbol: if we cannot match the parent
    function's name (or if there is no symbol because the function was inlined)
    we should still mark the variable as static to prevent it from matching
    a global variable with the same name."""
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0003:00000010], Flags: 00000000, "
        "?g_setBufferCount@?3??RendererCreateDevice@TglImpl@@YA?AW4Result@Tgl@@"
        "PAUIDirect3DRM2@@ABUDeviceDirectDrawCreateData@4@AAPAUIDirect3DRMDevice2@@@Z@4HA",
    )
    analysis = CvdumpAnalysis(parser, binfile)

    node = get_node(analysis, binfile.get_abs_addr(3, 0x10))
    assert node.friendly_name == "g_setBufferCount"
    assert node.static_var is True
    assert node.parent_function is None


@pytest.mark.parametrize(
    "name",
    (
        "?g_foo@@3HA",  # global variable
        "?x@Foo@@2HA",  # static member variable
    ),
)
def test_variable_in_publics_not_static_var(binfile: PEImage, name: str):
    """Should not assign static variable attributes to global variables."""
    parser = CvdumpParser()
    parser.read_section("PUBLICS", f"S_PUB32: [0003:00000010], Flags: 00000000, {name}")
    analysis = CvdumpAnalysis(parser, binfile)

    node = get_node(analysis, binfile.get_abs_addr(3, 0x10))
    assert node.static_var is False
    assert node.parent_function is None
