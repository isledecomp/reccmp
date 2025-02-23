from reccmp.isledecomp.formats import NEImage
from reccmp.isledecomp.formats.ne import NESegmentFlags, NETargetOSFlags


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
