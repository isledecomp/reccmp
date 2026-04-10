import pytest
from reccmp.formats import NEImage
from reccmp.formats.image import ImageImport
from reccmp.formats.ne import NESegmentFlags, NETargetOSFlags, NEEntry


def test_vitals(skifree: NEImage):
    # Linker version 5.5
    assert (skifree.header.ne_ver, skifree.header.ne_rev) == (5, 5)
    assert skifree.header.ne_enttab == 0x526
    assert skifree.header.ne_cbenttab == 0x88
    assert skifree.header.ne_heap == 0x4000
    assert skifree.header.ne_stack == 0x4000
    assert skifree.header.ne_flags == NESegmentFlags.NEINST | NESegmentFlags.NEWINAPI
    assert skifree.header.ne_exetyp == NETargetOSFlags.NE_WINDOWS
    assert skifree.header.ne_flagsothers == 8  # according to ghidra

    assert skifree.imagebase == 0x10000000
    assert skifree.entry == 0x100051E1


def test_reads(skifree: NEImage):
    assert (
        skifree.read(0x10000000, 16)
        == b"\x1e\x58\x90\x45\x55\x8b\xec\x1e\x8e\xd8\x81\xec\x04\x01\x57\x56"
    )
    assert skifree.read_string(0x10080017) == b"[out o' memory]"

    # Read up to end of seg.
    # Skip relocation at 0x5a2a
    assert (
        skifree.read_string(0x10005A2C) == b"\x8b\xd0\x2b\xc0\x8b\xe5\x5d\x4d\xcb\x90"
    )


ADDR_CONVERSION_SAMPLES = (
    # Section starts
    ((1, 0), 0x10000000),
    ((2, 0), 0x10080000),
    # Section ends (virtual size - 1)
    ((1, 0x5A35), 0x10005A35),
    ((2, 0x0BC7), 0x10080BC7),
)


@pytest.mark.parametrize("relative, absolute", ADDR_CONVERSION_SAMPLES)
def test_addr_conversion_absolute(
    skifree: NEImage, relative: tuple[int, int], absolute: int
):
    """Testing conversion from seg:offset to absolute address."""
    assert skifree.get_abs_addr(*relative) == absolute


@pytest.mark.parametrize("relative, absolute", ADDR_CONVERSION_SAMPLES)
def test_addr_conversion_relative(
    skifree: NEImage, relative: tuple[int, int], absolute: int
):
    """Testing conversion from absolute address to seg:offset."""
    assert skifree.get_relative_addr(absolute) == relative


def test_reloc_patching_import_ordinal(skifree: NEImage):
    # Source chain of one: the reloc location is 0xffff.
    # Just assert that we changed it to something else.
    assert skifree.read(0x10000049, 5) != b"\x9a\xff\xff\x00\x00"

    # USER::LOADSTRING -> import_seg::000f8
    assert skifree.read(0x10000049, 3) == b"\x9a\xf8\x00"


def test_reloc_patching_internalref(skifree: NEImage):
    # Internalref reloc has all zeroes for the pointer.
    assert skifree.read(0x10003C92, 5) != b"\x9a\x00\x00\x00\x00"

    # Should replace with 0001:3c92.
    assert skifree.read(0x10003C92, 5) == b"\x9a\x6e\x52\x00\x10"

    # Separate relocs for seg and offset.
    assert skifree.read(0x10003E71, 2) == b"\x3c\x51"
    assert skifree.read(0x10003E76, 2) == b"\x00\x10"


def test_reloc_patching_movable_segment(skifree: NEImage):
    assert skifree.read(0x10003E13, 2) != b"\x00\x00"

    assert skifree.read(0x10003E13, 2) == b"\x9a\x4c"

    # Chain:
    assert skifree.read(0x1000164C, 4) != b"\x6b\x16\x00\x00"
    assert skifree.read(0x1000166B, 4) != b"\x21\x16\x00\x00"
    assert skifree.read(0x10001621, 4) != b"\xff\xff\x00\x00"

    # FAR ADDR
    assert skifree.read(0x1000164C, 4) == b"\x7e\x53\x00\x10"
    assert skifree.read(0x1000166B, 4) == b"\x7e\x53\x00\x10"
    assert skifree.read(0x10001621, 4) == b"\x7e\x53\x00\x10"


def test_entry_table():
    # Windows 3.1 MPLAYER.EXE: entry table with skipped ordinals.
    # MPLAYER SHA256: 6b9385e9add45bd59ca7a20ebe55ff068f9dddb20dc2ab73701814fe0efba9aa
    data = (
        b"\x16\xff\x01\xcd\x3f\x01\x12\x1b\x01\xcd\x3f\x01\x10\x63\x01\xcd"
        b"\x3f\x01\x52\xa0\x01\xcd\x3f\x01\x6a\xad\x01\xcd\x3f\x01\xc6\xa3"
        b"\x01\xcd\x3f\x01\xc8\x98\x01\xcd\x3f\x01\x6a\xb8\x01\xcd\x3f\x01"
        b"\x34\x5b\x01\xcd\x3f\x01\xae\x7e\x01\xcd\x3f\x03\xf2\x0c\x01\xcd"
        b"\x3f\x03\x40\x0d\x01\xcd\x3f\x03\x86\x0d\x01\xcd\x3f\x03\xd4\x0d"
        b"\x01\xcd\x3f\x03\x14\x0e\x01\xcd\x3f\x03\x5e\x0b\x01\xcd\x3f\x03"
        b"\xca\x0b\x01\xcd\x3f\x01\x10\x00\x01\xcd\x3f\x01\xea\xa1\x01\xcd"
        b"\x3f\x01\xca\x8f\x01\xcd\x3f\x01\x94\x3b\x01\xcd\x3f\x01\xee\x36"
        b"\x01\xcd\x3f\x03\x36\x21\x07\x00\x08\xff\x01\xcd\x3f\x03\x56\x0e"
        b"\x01\xcd\x3f\x03\x6c\x0e\x01\xcd\x3f\x03\xe0\x0e\x01\xcd\x3f\x03"
        b"\xaa\x10\x01\xcd\x3f\x03\x94\x0e\x01\xcd\x3f\x03\xca\x0e\x01\xcd"
        b"\x3f\x03\x10\x0f\x01\xcd\x3f\x03\xfa\x0e\x03\x00\x09\xff\x01\xcd"
        b"\x3f\x03\x4e\x13\x01\xcd\x3f\x03\xa0\x13\x01\xcd\x3f\x03\xba\x19"
        b"\x01\xcd\x3f\x03\xd4\x19\x01\xcd\x3f\x03\x02\x1b\x01\xcd\x3f\x03"
        b"\x76\x1a\x01\xcd\x3f\x03\x78\x1c\x01\xcd\x3f\x03\x62\x1c\x01\xcd"
        b"\x3f\x03\x4c\x1c\x00"
    )

    entries = NEEntry.from_memory(data)
    assert entries[-1].ordinal == 43
    assert len(entries) < 43


IMPORT_REFS = (
    ImageImport(module="GDI", ordinal=34, addr=0x2000004C),
    ImageImport(module="KERNEL", ordinal=137, addr=0x20000040),
    ImageImport(module="USER", ordinal=420, addr=0x20000100),
)


@pytest.mark.parametrize("import_ref", IMPORT_REFS)
def test_imports(import_ref: tuple[ImageImport, ...], skifree: NEImage):
    assert import_ref in tuple(skifree.imports)
