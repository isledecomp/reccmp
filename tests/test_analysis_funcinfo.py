"""Test our detection of SEH data for PE images"""

from reccmp.isledecomp.formats import PEImage
from reccmp.isledecomp.analysis.funcinfo import (
    find_eh_handlers,
    find_funcinfo,
)


def test_funcinfo_count(binfile: PEImage):
    assert len(list(find_funcinfo(binfile))) == 1269


def test_funcinfo_exclude_noise(binfile: PEImage):
    handlers = [addr for (addr, _) in find_eh_handlers(binfile)]

    # `mov eax, -1` followed by `jmp`
    assert 0x10033FBF not in handlers


def test_funcinfo_handlers(binfile: PEImage):
    # Function "Score::DeleteScript" at 10001340.
    # The SEH handler is at 100013f5.
    matching_handlers = [
        (addr, f) for (addr, f) in find_eh_handlers(binfile) if addr == 0x100013F5
    ]

    assert len(matching_handlers) == 1

    (_, funcinfo) = matching_handlers[0]

    # Order does not seem to be relevant
    assert sorted(funcinfo.unwinds) == [(-1, 0x100013FF), (0, 0x100013ED)]
