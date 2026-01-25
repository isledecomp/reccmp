"""Tests for the pe module that:
1. Parses relevant data from the PE header and other structures.
2. Provides an interface to read from the DLL or EXE using a virtual address.
These are some basic smoke tests."""

import pytest
from reccmp.decomp.formats.image import ImageImport, ImageSectionFlags
from reccmp.decomp.formats import PEImage
from reccmp.decomp.formats.exceptions import (
    SectionNotFoundError,
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)


# The section layout for the `binfile` fixture is:
#
#     name │    start │   v.size │ raw size
# ─────────┼──────────┼──────────┼─────────
#    .text │ 10001000 │    d2a66 │    d2c00
#   .rdata │ 100d4000 │    1b5b6 │    1b600
#    .data │ 100f0000 │    1a734 │    12c00
#   .idata │ 1010b000 │     1006 │     1200
#    .rsrc │ 1010d000 │     21d8 │     2200
#   .reloc │ 10110000 │    10c58 │    10e00


def test_basic(binfile: PEImage):
    assert binfile.entry == 0x1008C860
    assert len(binfile.sections) == 6

    with pytest.raises(SectionNotFoundError):
        binfile.get_section_by_name(".hello")


SECTION_INFO = (
    (".text", 0x10001000, 0xD2A66, 0xD2C00),
    (".rdata", 0x100D4000, 0x1B5B6, 0x1B600),
    (".data", 0x100F0000, 0x1A734, 0x12C00),
    (".idata", 0x1010B000, 0x1006, 0x1200),
    (".rsrc", 0x1010D000, 0x21D8, 0x2200),
    (".reloc", 0x10110000, 0x10C58, 0x10E00),
)


@pytest.mark.parametrize("name, v_addr, v_size, raw_size", SECTION_INFO)
def test_sections(name: str, v_addr: int, v_size: int, raw_size: int, binfile: PEImage):
    section = binfile.get_section_by_name(name)
    assert section.virtual_address == v_addr
    assert section.virtual_size == v_size
    assert section.size_of_raw_data == raw_size


DOUBLE_PI_BYTES = b"\x18\x2d\x44\x54\xfb\x21\x09\x40"

# Now that's a lot of pi
PI_ADDRESSES = (
    0x100D4000,
    0x100D4700,
    0x100D7180,
    0x100DB8F0,
    0x100DC030,
)


@pytest.mark.parametrize("addr", PI_ADDRESSES)
def test_read_pi(addr: int, binfile: PEImage):
    assert binfile.read(addr, 8) == DOUBLE_PI_BYTES


def test_unusual_reads(binfile: PEImage):
    """Reads that return an error or some specific value based on context"""
    # Reading an address earlier than the imagebase
    with pytest.raises(InvalidVirtualAddressError):
        binfile.read(0, 1)

    # Really big address
    with pytest.raises(InvalidVirtualAddressError):
        binfile.read(0xFFFFFFFF, 1)

    # Initialized bytes for .data end at 0x10102c00. Read from the uninitialized section.
    # Older versions of reccmp would return None for uninitialized data.
    # We now return zeroes to emulate the behavior of the real program.
    assert binfile.read(0x1010A600, 4) == b"\x00\x00\x00\x00"

    # Read the last 16 initialized bytes of .data
    assert len(binfile.read(0x10102BF0, 16)) == 16

    # Keep reading into the uninitialized section without an exception.
    assert len(binfile.read(0x10102BF0, 32)) == 32

    # Read 8 initialized and 8 uninitialized bytes. Should pad with zeroes.
    assert binfile.read(0x10102BF8, 16) == (b"\x00" * 16)

    # Unlike .data, physical size for .text is larger than virtual size.
    # This means the padding bytes are stored in the file.
    # Read the unused but initialized bytes.
    assert binfile.read(0x100D3A70, 4) == b"\x00\x00\x00\x00"

    # .text ends at 0x100d3c00. Even though .rdata does not begin until 0x100d4000,
    # we still should not read past the end of virtual data.
    with pytest.raises(InvalidVirtualReadError):
        binfile.read(0x100D3BFF, 10)

    # Read past the final virtual address in .reloc
    with pytest.raises(InvalidVirtualReadError):
        binfile.read(0x10120DF0, 32)

    # Reading zero bytes is okay
    assert binfile.read(0x100DB588, 0) == b""

    # Cannot read with negative size
    with pytest.raises(InvalidVirtualReadError):
        binfile.read(0x100DB588, -1)

    # This should not fail.
    assert binfile.read_string(0x1010BFFC) == b"d3drm.dll"


STRING_ADDRESSES = (
    (0x100DB588, b"November"),
    (0x100F0130, b"Helicopter"),
    (0x100F0144, b"HelicopterState"),
    (0x100F0BE4, b"valerie"),
    (0x100F4080, b"TARGET"),
)


@pytest.mark.parametrize("addr, string", STRING_ADDRESSES)
def test_strings(addr: int, string: bytes, binfile: PEImage):
    """Test string read utility function and the string search feature"""
    assert binfile.read_string(addr) == string


def test_widechar(binfile: PEImage):
    assert binfile.read_widechar(0x100DAAA0) == "(null)".encode("utf-16-le")


def test_relocation(binfile: PEImage):
    # n.b. This is not the number of *relocations* read from .reloc.
    # It is the set of unique addresses in the binary that get relocated.
    assert len(binfile.get_relocated_addresses()) == 14066

    # Score::Score is referenced only by CALL instructions. No need to relocate.
    assert binfile.is_relocated_addr(0x10001000) is False

    # MxEntity::SetEntityId is in the vtable and must be relocated.
    assert binfile.is_relocated_addr(0x10001070) is True


# Not sanitizing dll name case. Do we care?
IMPORT_REFS = (
    ImageImport(module="KERNEL32.dll", name="CreateMutexA", addr=0x1010B3D0),
    ImageImport(module="WINMM.dll", name="midiOutPrepareHeader", addr=0x1010B550),
)


@pytest.mark.parametrize("import_ref", IMPORT_REFS)
def test_imports(import_ref: tuple[str, str, int], binfile: PEImage):
    assert import_ref in tuple(binfile.imports)


def test_exports(binfile: PEImage):
    assert len(binfile.exports) == 130
    assert (0x1003BFB0, b"??0LegoBackgroundColor@@QAE@PBD0@Z") in binfile.exports
    assert (0x10091EE0, b"_DllMain@12") in binfile.exports


def test_section_not_found_error(binfile: PEImage):
    with pytest.raises(SectionNotFoundError):
        binfile.get_section_by_index(0)

    with pytest.raises(SectionNotFoundError):
        binfile.get_section_by_index(7)

    with pytest.raises(SectionNotFoundError):
        binfile.get_section_by_name("text")

    with pytest.raises(SectionNotFoundError):
        binfile.get_section_by_name(".text\x00")


def test_is_valid_section(binfile: PEImage):
    """Should not raise exception for an invalid section."""
    assert binfile.is_valid_section(0) is False
    assert binfile.is_valid_section(7) is False

    for i in range(1, 7):
        assert binfile.is_valid_section(i) is True


ADDR_CONVERSION_SAMPLES = (
    # Section starts
    ((1, 0), 0x10001000),
    ((2, 0), 0x100D4000),
    ((3, 0), 0x100F0000),
    ((4, 0), 0x1010B000),
    ((5, 0), 0x1010D000),
    ((6, 0), 0x10110000),
    # Section ends (virtual size - 1)
    ((1, 0xD2A65), 0x10001000 + 0xD2A65),
    ((2, 0x1B5B5), 0x100D4000 + 0x1B5B5),
    ((3, 0x1A733), 0x100F0000 + 0x1A733),
    ((4, 0x01005), 0x1010B000 + 0x01005),
    ((5, 0x021D7), 0x1010D000 + 0x021D7),
    ((6, 0x10C57), 0x10110000 + 0x10C57),
)


@pytest.mark.parametrize("relative, absolute", ADDR_CONVERSION_SAMPLES)
def test_addr_conversion_absolute(
    binfile: PEImage, relative: tuple[int, int], absolute: int
):
    """Testing conversion from seg:offset to absolute address."""
    assert binfile.get_abs_addr(*relative) == absolute


@pytest.mark.parametrize("relative, absolute", ADDR_CONVERSION_SAMPLES)
def test_addr_conversion_relative(
    binfile: PEImage, relative: tuple[int, int], absolute: int
):
    """Testing conversion from absolute address to seg:offset."""
    assert binfile.get_relative_addr(absolute) == relative


def test_section_flags(binfile: PEImage):
    code = [s.name for s in binfile.sections if s.flags & ImageSectionFlags.EXECUTE]
    assert code == [".text"]

    readable = [s.name for s in binfile.sections if s.flags & ImageSectionFlags.READ]
    assert readable == [".text", ".rdata", ".data", ".idata", ".rsrc", ".reloc"]

    writable = [s.name for s in binfile.sections if s.flags & ImageSectionFlags.WRITE]
    assert writable == [".data", ".idata"]
