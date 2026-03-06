"""Test our detection of SEH data for PE images"""

from reccmp.formats import PEImage
from reccmp.analysis.funcinfo import (
    UnwindMapEntry,
    find_mov_eax_jmp_in_buffer,
    find_eh_handlers,
    find_funcinfo,
)


def test_detect_handler_overlap():
    """Must be able to match potential instructions that overlap.
    Because we are not disassembling, we don't know whether a given
    byte is the start of an instruction."""
    code = b"\xb8\x00\x00\xb8\x00\xe9\x00\x00\xe9"
    handlers = list(find_mov_eax_jmp_in_buffer(code))
    assert len(handlers) == 2


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
    assert sorted(funcinfo.unwinds) == [
        UnwindMapEntry(-1, 0x100013FF),
        UnwindMapEntry(0, 0x100013ED),
    ]
