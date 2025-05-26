"""Test find_vtordisp for PE images"""

from reccmp.isledecomp.formats import PEImage
from reccmp.isledecomp.analysis.vtordisp import find_vtordisp, find_displacements


def test_vtor_overlap():
    """Must be able to match potential instructions that overlap.
    Because we are not disassembling, we don't know whether a given
    byte is the start of an instruction."""
    code = b"\x2b\x49\xfc\xe9\x2b\x49\xfc\xe9\x08\x00\x00\x00"
    vtors = list(find_displacements(code))
    assert len(vtors) == 2


def test_detection(binfile: PEImage):
    """Make sure we detect some known floats in our sample PE image"""
    vtors = list(find_vtordisp(binfile))

    # {byte, 0}
    assert (0x1000FBB0, (-4, 0), 0x1000FBC0) in vtors

    # {byte, dword}
    assert (0x10014CD0, (-4, 4294966924), 0x1001C290) in vtors

    # {byte, byte}
    assert (0x100432B0, (-4, 64), 0x1001C870) in vtors
