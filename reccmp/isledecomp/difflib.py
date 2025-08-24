"""Wrappers and items related to the builtin python difflib module."""

from typing import Iterator


DiffOpcode = tuple[str, int, int, int, int]


def get_grouped_opcodes(
    codes: list[DiffOpcode], n: int = 3
) -> Iterator[list[DiffOpcode]]:
    """
    Taken from the Python 3.12 standard library, `difflib.py`, published under PSF license, GPL compatible.
    """

    if not codes:
        codes = [("equal", 0, 1, 0, 1)]
    # Fixup leading and trailing groups if they show no changes.
    if codes[0][0] == "equal":
        tag, i1, i2, j1, j2 = codes[0]
        codes[0] = tag, max(i1, i2 - n), i2, max(j1, j2 - n), j2
    if codes[-1][0] == "equal":
        tag, i1, i2, j1, j2 = codes[-1]
        codes[-1] = tag, i1, min(i2, i1 + n), j1, min(j2, j1 + n)

    nn = n + n
    group = []
    for tag, i1, i2, j1, j2 in codes:
        # End the current group and start a new one whenever
        # there is a large range with no changes.
        if tag == "equal" and i2 - i1 > nn:
            group.append((tag, i1, min(i2, i1 + n), j1, min(j2, j1 + n)))
            yield group
            group = []
            i1, j1 = max(i1, i2 - n), max(j1, j2 - n)
        group.append((tag, i1, i2, j1, j2))
    if group and not (len(group) == 1 and group[0][0] == "equal"):
        yield group
