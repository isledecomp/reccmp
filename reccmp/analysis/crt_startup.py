import enum
import struct
from dataclasses import dataclass, field
from typing import Iterator
from reccmp.analysis.xref import FunctionXrefMap, Xref, get_function_xrefs
from reccmp.formats import Image
from reccmp.types import ImageId
from reccmp.compare.db import EntityDb


class CrtStartupArrayType(enum.Enum):
    C_INIT = enum.auto()
    CPP_INIT = enum.auto()
    C_PRE_TERM = enum.auto()
    C_TERM = enum.auto()


_CRT_STARTUP_ARRAY_BOUNDARIES = {
    CrtStartupArrayType.C_INIT: ("___xi_a", "___xi_z"),
    CrtStartupArrayType.CPP_INIT: ("___xc_a", "___xc_z"),
    CrtStartupArrayType.C_PRE_TERM: ("___xp_a", "___xp_z"),
    CrtStartupArrayType.C_TERM: ("___xt_a", "___xt_z"),
}

_CRT_STARTUP_ARRAY_LABELS = [
    label for pair in _CRT_STARTUP_ARRAY_BOUNDARIES.values() for label in pair
]


_CRT_FUNCTION_NAMES = {
    CrtStartupArrayType.C_INIT: "$CRT_C_Initializer",
    CrtStartupArrayType.CPP_INIT: "$CRT_CPP_Initializer",
    CrtStartupArrayType.C_PRE_TERM: "$CRT_C_Pre-Terminator",
    CrtStartupArrayType.C_TERM: "$CRT_C_Terminator",
}


def get_crt_function_name(type_: CrtStartupArrayType) -> str:
    return _CRT_FUNCTION_NAMES[type_]


@dataclass
class CrtStartupArray:
    """Result from analyzing functions in a CRT startup array.
    The functions within are called either before startup or during shutdown.
    For example: addresses of C++ initializer functions are between
    the labels ___xc_a and ___xc_z."""

    entries: list[int] = field(default_factory=list)
    """The addresses in the array."""

    function_set: dict[int, tuple[int, ...]] = field(default_factory=dict)
    """Maps the array entry address to the addresses of related functions."""

    xrefs: FunctionXrefMap = field(default_factory=dict)
    """Maps the array entry to a list of xrefs: addresses used in the function set."""


def read_crt_array(binfile: Image, span: range) -> Iterator[int]:
    """Read 4-byte (dword) pointers from the specified range.
    Excludes the first element, a zero."""
    try:
        for (addr,) in struct.iter_unpack("<I", binfile.read(span.start, len(span))):
            if addr != 0:
                yield addr
    except struct.error:
        # Don't crash on bad user input: the start or end addrs are incorrect
        pass


def find_crt_startup_labels(db: EntityDb, image_id: ImageId) -> dict[str, int]:
    found = {}

    for ent in db.all(image_id):
        name = ent.get("name")
        if name is not None and name in _CRT_STARTUP_ARRAY_LABELS:
            addr = ent.addr(image_id)
            assert isinstance(addr, int)
            found[name] = addr

            if len(found) == len(_CRT_STARTUP_ARRAY_LABELS):
                break

    return found


JMP_THUNKS = {b"\xe9\x00\x00\x00\x00", b"\xe9\x0b\x00\x00\x00"}
"""Observed thunk patterns for C++ init: jump to a single function, located
either directly after the thunk or at the next 16-byte boundary."""

CALL_JMP_THUNKS = {b"\xe8\x05\x00\x00\x00\xe9", b"\xe8\x0b\x00\x00\x00\xe9"}
"""Observed thunk patterns for C++ init: call the first function, then jump to
the second. The position of the second function depends on the size of the first,
so its displacement is not part of the pattern."""


def read_function_set(binfile: Image, addr: int) -> tuple[int, ...]:
    """For the given address of a function in a CRT startup array, return the list of
    connected functions that follow specific patterns. For example, in the C++ initializer
    array, we have observed two thunk patterns that point to:
    1. JMP only:    Initializer function
    2. CALL + JMP:  Initializer function, atexit destructor setter function"""
    data = binfile.read(addr, 10)
    first_disp, second_disp = struct.unpack("<xixi", data)

    if data[:5] in JMP_THUNKS:
        return (addr + 5 + first_disp,)

    # In the CALL + JMP pattern, we cannot predict the JMP operand value because
    # the displacement depends on the size of the function in the CALL instruction.
    # However, the trend is that the three functions are in sequence, so allow
    # a forward jump only.
    if data[:6] in CALL_JMP_THUNKS and second_disp >= 0:
        return (addr + 5 + first_disp, addr + 10 + second_disp)

    return ()


def read_crt_functions(binfile: Image, span: range) -> CrtStartupArray:
    """Create the CRT array structure using the given range of addresses.
    For each function in the array that matches a known thunk pattern,
    "unwrap" the indirection and add the related functions to the list."""
    array = CrtStartupArray()
    # n.b. The first value in the array is zero. It was excluded by read_crt_array.
    for addr in read_crt_array(binfile, span):
        array.entries.append(addr)
        function_set = read_function_set(binfile, addr)
        if function_set:
            array.function_set[addr] = function_set

    return array


def collect_crt_xrefs(
    db: EntityDb, image_id: ImageId, binfile: Image, array: CrtStartupArray
):
    """Update the CRT array structure with the xrefs of each function."""
    xrefs: dict[int, tuple[Xref, ...]] = {}
    for entry in array.entries:
        # If the entry in the array is a thunk for a function set, sample the functions
        # from the set instead.
        sampled_funcs = array.function_set.get(entry, (entry,))

        # Xrefs are pooled together for all functions in the set.
        entry_xrefs = tuple(
            xref
            for addr in sampled_funcs
            for xref in get_function_xrefs(db, image_id, binfile, addr)
        )

        if entry_xrefs:
            xrefs[entry] = entry_xrefs

    array.xrefs = xrefs


def iter_crt_array_ranges(
    db: EntityDb, image_id: ImageId
) -> Iterator[tuple[CrtStartupArrayType, range]]:
    """For each CRT array whose start and end labels are known, return the array type and address range."""
    labels = find_crt_startup_labels(db, image_id)
    for array_type, (label_start, label_end) in _CRT_STARTUP_ARRAY_BOUNDARIES.items():
        if label_start in labels and label_end in labels:
            array_range = range(labels[label_start], labels[label_end])
            yield (array_type, array_range)


def detect_crt_startup_arrays(
    db: EntityDb, image_id: ImageId, binfile: Image
) -> dict[CrtStartupArrayType, CrtStartupArray]:
    """Return a map of CRT startup array types to each list of functions."""
    return {
        array_type: read_crt_functions(binfile, array_range)
        for array_type, array_range in iter_crt_array_ranges(db, image_id)
    }


def match_function_sets(
    orig_array: CrtStartupArray,
    recomp_array: CrtStartupArray,
    pairs: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Return a list of matches between functions in the two CRT startup arrays.
    The input list `pairs` contains the array entry addresses matched by xref.
    Expand the list so that members of the function sets are matched."""
    matches: list[tuple[int, int]] = []
    for orig_entry, recomp_entry in pairs:
        assert orig_entry in orig_array.entries
        assert recomp_entry in recomp_array.entries

        # Check whether the arrays have a function set for this entry.
        orig_set = orig_array.function_set.get(orig_entry, ())
        recomp_set = recomp_array.function_set.get(recomp_entry, ())

        if orig_set and recomp_set:
            # Both arrays used a thunk for this entry.
            # If one side used the JMP pattern and the other used CALL + JMP,
            # match the first function in the set only.
            matches.extend(zip(orig_set, recomp_set))
            matches.append((orig_entry, recomp_entry))

        # If one of the arrays has a thunk pattern but the other does not, we assume
        # (following the C++ init pattern) that the non-thunk function is the initializer.
        # Therefore: match the thunked initializer (first function) to the non-thunk in
        # the other array. The thunk on only one side is not matched.
        elif orig_set:
            matches.append((orig_set[0], recomp_entry))

        elif recomp_set:
            matches.append((orig_entry, recomp_set[0]))

        else:
            # Neither side used a thunk pattern, just match the entries directly.
            matches.append((orig_entry, recomp_entry))

    return matches
