"""Test find_float_const for PE images"""

from reccmp.isledecomp.formats import PEImage
from reccmp.isledecomp.analysis.float_const import (
    find_float_instructions_in_buffer,
    find_float_consts,
)


def test_float_detect_overlap():
    """Must be able to match potential instructions that overlap.
    Because we are not disassembling, we don't know whether a given
    byte is the start of an instruction."""
    code = b"\xd8\x05\xd8\x05\x00\x10\x00\x10"
    floats = list(find_float_instructions_in_buffer(code))
    assert len(floats) == 2


def test_basic_float_detection(binfile: PEImage):
    """Make sure we detect some known floats in our sample PE image"""
    floats = list(find_float_consts(binfile))

    # Single and double precision, same value
    assert (0x100DBD38, 4, 0.5) in floats
    assert (0x100D8BC0, 8, 0.5) in floats

    # Integer
    assert (0x100D6F88, 4, 1024.0) in floats

    # Both pi, both doubles, but different levels of precision
    assert (0x100DB8F0, 8, 3.141592653589793) in floats
    assert (0x100DBD50, 8, 3.14159265359) in floats


def test_floats_appear_once(binfile: PEImage):
    """Multiple instructions may point at the same constant.
    Our list should only return each constant once."""
    floats = list(find_float_consts(binfile))

    assert len(floats) == len(set(floats))
