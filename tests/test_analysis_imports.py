"""Test find_import_thunks for PE images"""

import pytest
from reccmp.isledecomp.formats import PEImage
from reccmp.isledecomp.analysis.imports import (
    find_absolute_jumps_in_bytes,
    find_import_thunks,
)


def test_absolute_jumps_overlap():
    code = b"\xff\x25\x00\x10\xff\x25\x00\x00\x00\x10"
    jumps = list(find_absolute_jumps_in_bytes(code))
    assert len(jumps) == 2


def test_lego1_import_thunks(binfile: PEImage):
    thunks = [(thunk.addr, thunk.import_addr) for thunk in find_import_thunks(binfile)]
    # D3DRMCreateColorRGBA
    assert (0x100D373A, 0x1010B590) in thunks
    # DirectDrawCreate
    assert (0x100D3728, 0x1010B32C) in thunks
    # RtlUnwind
    assert (0x10098F9E, 0x1010B3D4) in thunks


@pytest.mark.xfail(reason="Acknowledged limitation of this search.")
def test_should_ignore_get_system_cp(binfile: PEImage):
    """The MSVC Library function _getSystemCP is at 0x10091c50.
    It contains a jump to GetOEMCP from KERNEL32.DLL, but this itself is not a thunk.
    This function only searches for 6-byte JMPs an cannot tell whether the
    address is the start of a function. We can't use the relocation table to eliminate
    non-thunks because CALL instructions are relative (and not relocated)."""
    thunk_addrs = [thunk.addr for thunk in find_import_thunks(binfile)]
    assert 0x10091C6D not in thunk_addrs
