from textwrap import dedent
from reccmp.isledecomp.formats import PEImage
from reccmp.isledecomp.cvdump import CvdumpAnalysis, CvdumpParser
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.ingest import load_cvdump
from reccmp.isledecomp.types import EntityType


# These functions use our sample PE image to "cheat" and not have to mock as much.
# This sets up the imagebase and valid section boundaries for calculation inside load_cvdump.
# The seg:offsets and addresses in the tests match where strings and other items can be found.
# Strictly speaking this *should* be a fully mocked sample image, but this isn't
# easy with the current API. TODO: #190
#
# The addresses are calculated using this:
#
#     name │    start │   v.size │ raw size
# ─────────┼──────────┼──────────┼─────────
#    .text │ 10001000 │    d2a66 │    d2c00
#   .rdata │ 100d4000 │    1b5b6 │    1b600
#    .data │ 100f0000 │    1a734 │    12c00
#   .idata │ 1010b000 │     1006 │     1200
#    .rsrc │ 1010d000 │     21d8 │     2200
#   .reloc │ 10110000 │    10c58 │    10e00


def test_size_estimate(binfile: PEImage):
    """If there is no better size given for an entity, estimate the size
    based on the distance to the next entity in the same section.
    If there is no such entity, use the size of the section"""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        dedent(
            """\
        S_PUB32: [0003:0001292A], Flags: 00000000, __OP_LOG10jmptab
        S_PUB32: [0003:0001294A], Flags: 00000000, __OP_LOGjmptab
        """
        ),
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    # There are 32 bytes between this and __OP_LOGjmptab
    entity = db.get_by_recomp(0x1010292A)
    assert entity is not None
    assert entity.get("symbol") == "__OP_LOG10jmptab"
    assert entity.get("size") == 0x20

    # Calculate the distance to the end of the .data section.
    entity = db.get_by_recomp(0x1010294A)
    assert entity is not None
    assert entity.get("symbol") == "__OP_LOGjmptab"
    assert entity.get("size") == 0x100F0000 + 0x1A734 - 0x1010294A


def test_size_estimate_different_sections(binfile: PEImage):
    """Do not cross section boundaries when estimating size."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        dedent(
            """\
        S_PUB32: [0002:00000018], Flags: 00000000, ??_7Score@@6B@
        S_PUB32: [0003:0001292A], Flags: 00000000, __OP_LOG10jmptab
        """
        ),
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    # Calculate the distance to the end of the .rdata section.
    # n.b. The physical size is aligned to the image FileAlignment value
    # so it is used instead of the smaller virtual size.
    entity = db.get_by_recomp(0x100D4018)
    assert entity is not None
    assert entity.get("size") == 0x100D4000 + 0x1B600 - 0x100D4018

    # Calculate the distance to the end of the .data section.
    entity = db.get_by_recomp(0x1010292A)
    assert entity is not None
    assert entity.get("size") == 0x100F0000 + 0x1A734 - 0x1010292A


def test_size_estimate_section_contrib(binfile: PEImage):
    """If the entity has data from section contributions, use it as the size
    UNLESS the distance to the next entity is smaller."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        dedent(
            """\
        S_PUB32: [0003:0001292A], Flags: 00000000, __OP_LOG10jmptab
        S_PUB32: [0003:0001294A], Flags: 00000000, __OP_LOGjmptab
        S_PUB32: [0003:0001296A], Flags: 00000000, __OP_EXPjmptab
        """
        ),
    )
    parser.read_section(
        "SECTION CONTRIBUTIONS",
        dedent(
            """\
          0032  0003:0001292A  00000100  40303040
          0032  0003:0001294A  00000010  40303040
          0032  0003:0001296A  00000010  40303040
        """
        ),
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    # Distance to next entity is smaller than section contribution.
    entity = db.get_by_recomp(0x1010292A)
    assert entity is not None
    assert entity.get("symbol") == "__OP_LOG10jmptab"
    assert entity.get("size") == 0x20

    # Section contribution size is smaller than distance to next entity.
    entity = db.get_by_recomp(0x1010294A)
    assert entity is not None
    assert entity.get("symbol") == "__OP_LOGjmptab"
    assert entity.get("size") == 0x10

    # Prefer section contribution size over distance to end of section.
    entity = db.get_by_recomp(0x1010296A)
    assert entity is not None
    assert entity.get("symbol") == "__OP_EXPjmptab"
    assert entity.get("size") == 0x10


def test_no_entity_for_section_contributions_only(binfile: PEImage):
    """Do not create an entity if the only data we have is from SECTION CONTRIBUTIONS."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "SECTION CONTRIBUTIONS",
        "  0032  0003:0001292A  00000100  40303040",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    assert db.get_by_recomp(0x1010292A) is None


def test_symbol_overwrite(binfile: PEImage):
    """Library functions may have multiple linker names for the same address.
    New entries for the same address will overwrite the previous one."""

    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        dedent(
            """\
            S_PUB32: [0001:0008B410], Flags: 00000000, __strlwr
            S_PUB32: [0001:0008B410], Flags: 00000000, _strlwr
            """
        ),
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x1008C410)
    assert entity is not None
    assert entity.get("symbol") == "_strlwr"


def test_string_without_section_contrib(binfile: PEImage):
    """Can create the string entity even if we don't have the exact length
    from the entry in SECTION CONTRIBUTIONS."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0002:0000757C], Flags: 00000000, ??_C@_08LIDF@December?$AA@",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x100DB57C)
    assert entity is not None
    assert entity.get("type") == EntityType.STRING
    assert entity.get("symbol") == "??_C@_08LIDF@December?$AA@"

    # Name to be set later.
    assert entity.get("name") is None

    # Size will be determined after reading from the binary.
    assert entity.get("size") is None


def test_string_with_section_contrib(binfile: PEImage):
    """Can create the string entity using the length found in SECTION CONTRIBUTIONS.
    TODO: It would be better to showcase a string that contains nulls and thus cannot
    be read correctly using Image.read_string()."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0002:0000757C], Flags: 00000000, ??_C@_08LIDF@December?$AA@",
    )
    parser.read_section(
        "SECTION CONTRIBUTIONS",
        "  0032  0002:0000757C  00000009  40303040",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x100DB57C)
    assert entity is not None
    assert entity.get("type") == EntityType.STRING
    assert entity.get("symbol") == "??_C@_08LIDF@December?$AA@"

    # Name to be set later.
    assert entity.get("name") is None

    # Size includes null-terminator
    assert entity.get("size") == 9


def test_utf16_without_section_contrib(binfile: PEImage):
    """Can create the widechar entity even if we don't have the exact length
    from the entry in SECTION CONTRIBUTIONS."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0002:00006AA0], Flags: 00000000, ??_C@_1O@POHA@?$AA?$CI?$AAn?$AAu?$AAl?$AAl?$AA?$CJ?$AA?$AA?$AA?$AA?$AA?$AH?$AA?$AA?$AA?$AA?$AA?$AA?$AA?$9A?$AE?$;I@",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x100DAAA0)
    assert entity is not None
    assert entity.get("type") == EntityType.WIDECHAR
    assert (
        entity.get("symbol")
        == "??_C@_1O@POHA@?$AA?$CI?$AAn?$AAu?$AAl?$AAl?$AA?$CJ?$AA?$AA?$AA?$AA?$AA?$AH?$AA?$AA?$AA?$AA?$AA?$AA?$AA?$9A?$AE?$;I@"
    )

    # Name to be set later.
    assert entity.get("name") is None

    # Size will be determined after reading from the binary.
    assert entity.get("size") is None


def test_utf16_with_section_contrib(binfile: PEImage):
    """Can create the widechar entity using the length found in SECTION CONTRIBUTIONS."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0002:00006AA0], Flags: 00000000, ??_C@_1O@POHA@?$AA?$CI?$AAn?$AAu?$AAl?$AAl?$AA?$CJ?$AA?$AA?$AA?$AA?$AA?$AH?$AA?$AA?$AA?$AA?$AA?$AA?$AA?$9A?$AE?$;I@",
    )
    parser.read_section(
        "SECTION CONTRIBUTIONS",
        "  00FA  0002:00006AA0  0000000E  40303040",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x100DAAA0)
    assert entity is not None
    assert entity.get("type") == EntityType.WIDECHAR
    assert (
        entity.get("symbol")
        == "??_C@_1O@POHA@?$AA?$CI?$AAn?$AAu?$AAl?$AAl?$AA?$CJ?$AA?$AA?$AA?$AA?$AA?$AH?$AA?$AA?$AA?$AA?$AA?$AA?$AA?$9A?$AE?$;I@"
    )

    # Name to be set later.
    assert entity.get("name") is None

    # Size includes two-byte null-terminator
    assert entity.get("size") == 14


def test_vtable(binfile: PEImage):
    """Should create vtable entity from linker name."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0002:00000018], Flags: 00000000, ??_7Score@@6B@",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x100D4018)
    assert entity is not None
    assert entity.get("type") == EntityType.VTABLE
    assert entity.get("name") == "Score::`vftable'"
    assert entity.get("symbol") == "??_7Score@@6B@"


def test_vtable_with_vbclass(binfile: PEImage):
    """Should create vtable entity with virtual base class (multiple inheritance)."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0002:00002860], Flags: 00000000, ??_7BumpBouy@@6BOgelAnimActor@@@",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x100D6860)
    assert entity is not None
    assert entity.get("type") == EntityType.VTABLE
    assert entity.get("name") == "BumpBouy::`vftable'{for `OgelAnimActor'}"
    assert entity.get("symbol") == "??_7BumpBouy@@6BOgelAnimActor@@@"


def test_vbtable(binfile: PEImage):
    """Should create vbtable entity from linker name."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0002:00002788], Flags: 00000000, ??_8BumpBouy@@7B@",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x100D6788)
    assert entity is not None
    assert entity.get("type") == EntityType.DATA
    assert entity.get("name") == "BumpBouy::`vbtable'"
    assert entity.get("symbol") == "??_8BumpBouy@@7B@"
    # TODO: Is this just a number? We could assume the size based on nothing else.


def test_gdata32(binfile: PEImage):
    """Should create an entity from only an S_GDATA32 node in GLOBALS."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0002:000054F8], Flags: 00000000, ?g_pizzaHitSounds@@3PAW4Script@Act3Script@@A",
    )
    parser.read_section(
        "GLOBALS",
        "S_GDATA32: [0002:000054F8], Type:             0x5BB7, g_pizzaHitSounds",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x100D94F8)
    assert entity is not None
    assert entity.get("type") == EntityType.DATA
    assert entity.get("name") == "g_pizzaHitSounds"


def test_ldata32(binfile: PEImage):
    """Should create an entity from only an S_LDATA32 node in GLOBALS."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "GLOBALS",
        "S_LDATA32: [0002:00000000], Type:             0x5D8C, Pi",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x100D4000)
    assert entity is not None
    assert entity.get("type") == EntityType.DATA
    assert entity.get("name") == "Pi"


def test_variable_size_scalar_type(binfile: PEImage):
    """Should correctly set the size for a variable with scalar type.
    We don't currently need to preload the type database with any MSVC-specific data in order to do this. TODO: #106
    """
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0003:00012B24], Flags: 00000000, ?g_nextInterruptWavIndex@@3IA",
    )
    parser.read_section(
        "GLOBALS",
        "S_GDATA32: [0003:00012B24], Type:      T_UINT4(0075), g_nextInterruptWavIndex",
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x10102B24)
    assert entity is not None
    assert entity.get("size") == 4
    assert entity.get("name") == "g_nextInterruptWavIndex"


def test_variable_size_without_type_info(binfile: PEImage):
    """The variable is: char g_hdPath[1024].
    We cannot properly set the size without having information about its type."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS", "S_PUB32: [0003:000115B8], Flags: 00000000, ?g_hdPath@@3PADA"
    )
    parser.read_section(
        "GLOBALS",
        "S_GDATA32: [0003:000115B8], Type:             0x1424, g_hdPath",
    )
    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x101015B8)
    assert entity is not None
    assert entity.get("name") == "g_hdPath"

    # Asserting it this way because the current behavior is to estimate the entity size
    # using the distance between the address and the end of the section.
    assert entity.get("size") != 1024


def test_variable_size_with_type_info(binfile: PEImage):
    """Should cross-reference the type information to set the entity size correctly."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0003:000115B8], Flags: 00000000, ?g_hdPath@@3PADA",
    )
    parser.read_section(
        "GLOBALS",
        "S_GDATA32: [0003:000115B8], Type:             0x1424, g_hdPath",
    )
    parser.read_section(
        "TYPES",
        dedent(
            """\
            0x1424 : Length = 14, Leaf = 0x1503 LF_ARRAY
                Element type = T_RCHAR(0070)
                Index type = T_SHORT(0011)
                length = 1024
                Name = 
        """
        ),
    )
    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x101015B8)
    assert entity is not None
    assert entity.get("size") == 1024


def test_gproc32(binfile: PEImage):
    """Should create a function entity from only an S_GPROC32 block in SYMBOLS."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "SYMBOLS",
        dedent(
            """\
        (00038C) S_GPROC32: [0001:00037220], Cb: 0000008B, Type:             0x2068, Pizza::Start
                 Parent: 00000000, End: 000003E8, Next: 00000000
                 Debug start: 00000001, Debug end: 00000087

        (0003C0)  S_REGISTER: esi, Type:             0x2055, this
        (0003D0)  S_BPREL32: [00000004], Type:             0x1134, p_objectId

        (0003E8) S_END
        """
        ),
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x10038220)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION
    assert entity.get("size") == 0x8B
    assert entity.get("name") == "Pizza::Start"


def test_lproc32(binfile: PEImage):
    """Should create a function entity from only an S_LPROC32 block in SYMBOLS."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "SYMBOLS",
        dedent(
            """\
        (0000A8) S_LPROC32: [0001:00091350], Cb: 00000005, Type:             0x164F, $E28
                 Parent: 00000000, End: 000000D4, Next: 00000000
                 Debug start: 00000000, Debug end: 00000005
        """
        ),
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    # This is one of the ___xc_a functions.
    entity = db.get_by_recomp(0x10092350)
    assert entity is not None
    assert entity.get("type") == EntityType.FUNCTION
    assert entity.get("size") == 5
    assert entity.get("name") == "$E28"


def test_invalid_seg_ofs(binfile: PEImage):
    """Should skip entities that are outside the sections defined in the image headers."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0008:00000000], Flags: 00000000, __except_list",
    )

    cvdump_analysis = CvdumpAnalysis(parser)

    # Make sure we read it
    assert cvdump_analysis.nodes

    # No exception raised
    load_cvdump(cvdump_analysis, db, binfile)


def test_gproc_with_static_var(binfile: PEImage):
    """Should create entities for static variables using S_LDATA32 embedded in S_GPROC32."""

    db = EntityDb()
    parser = CvdumpParser()

    # This is a real function and static variable, but the cvdump output is made up.
    # MSVC 4.20 doesn't indicate static variables like this.
    parser.read_section(
        "SYMBOLS",
        dedent(
            """\
        (000780) S_GPROC32: [0001:0009CA20], Cb: 00000051, Type:             0x234C, EnableResizing
                 Parent: 00000000, End: 000007EC, Next: 00000000
                 Debug start: 00000007, Debug end: 0000004E

        (0007B8)  S_BPREL32: [00000004], Type:    T_32PVOID(0403), p_hwnd
        (0007CC)  S_LDATA32: [0003:00019594], Type:       T_UINT4(0075), g_dwStyle

        (0007EC) S_END
        """
        ),
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    entity = db.get_by_recomp(0x10109594)
    assert entity is not None
    assert entity.get("type") == EntityType.DATA
    assert entity.get("name") == "g_dwStyle"

    # We can get the size from just the scalar type for now.
    # We may need to preload the types db with MSVC-specific data later. TODO: #106
    assert entity.get("size") == 4

    # TODO: #102. The parent function's address should be set instead.
    symbol = entity.get("symbol")
    assert symbol is not None
    assert "g_dwStyle" in symbol
    assert "EnableResizing" in symbol


def test_floats(binfile: PEImage):
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        dedent(
            """\
        S_PUB32: [0002:00001740], Flags: 00000000, __real@4@00000000000000000000
        S_PUB32: [0002:00001748], Flags: 00000000, __real@8@00000000000000000000
        """
        ),
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    # Zero in single precision
    entity = db.get_by_recomp(0x100D5740)
    assert entity is not None
    assert entity.get("symbol") == "__real@4@00000000000000000000"
    assert entity.get("type") == EntityType.FLOAT
    assert entity.get("size") == 4

    # The name will be blank until we read from the binary in a later step.
    assert entity.get("name") is None

    # Zero in double precision
    entity = db.get_by_recomp(0x100D5748)
    assert entity is not None
    assert entity.get("symbol") == "__real@8@00000000000000000000"
    assert entity.get("type") == EntityType.FLOAT
    assert entity.get("size") == 8
    assert entity.get("name") is None


def test_skip_global_without_matching_public(binfile: PEImage):
    """Do not create an entity for S_GDATA32 leaves from the GLOBALS section that
    do not have a corresponding leaf in PUBLICS."""
    db = EntityDb()
    parser = CvdumpParser()
    parser.read_section(
        "PUBLICS",
        "S_PUB32: [0004:0002F6BC], Flags: 00000000, ?g_infomainScript@@3PAVMxAtomId@@A",
    )
    parser.read_section(
        "GLOBALS",
        dedent(
            """\
        S_GDATA32: [0004:0002F6BC], Type:             0x10D5, g_infomainScript
        S_GDATA32: [0004:0000C718], Type:             0x10D5, g_infomainScript
        """
        ),
    )

    cvdump_analysis = CvdumpAnalysis(parser)
    load_cvdump(cvdump_analysis, db, binfile)

    # Should skip the entry at 0004:0000C718
    assert db.get_by_recomp(0x101DF718) is None

    # Should create an entry at 0004:0002F6BC
    assert db.get_by_recomp(0x1013A6BC) is not None
