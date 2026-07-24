"""Fold-aware equivalence groups for operand comparison.

Some original binaries contain groups of addresses that are proven
machine-equivalent by external tooling and should be interchangeable when
comparing operands:

- per-TU duplicate template COMDAT bodies (the same instantiation emitted once
  per referencing translation unit, identical modulo relocations);
- incremental-link fold islands (a moved/folded symbol's old address holds a
  stale ``jmp rel32`` island whose chain lands on one shared final body, e.g.
  MSVC LINK 5.0 incremental images).

A project declares these groups in one or more ``equivalence-groups`` files
(``reccmp-project.yml`` target key). Each non-comment line is pipe-separated
with at least two fields: ``member_orig_address|canonical_orig_address``;
further fields (names, classifications) are project metadata and are ignored
here. reccmp trusts the file: the body-equivalence proof is the project's
responsibility (e.g. a repo gate re-verifying every row).

During comparison, any reference that resolves to a group member is treated as
a reference to the group canonical — for CALL/indirect operand names and for
vtable slot pairing — so an original call into a member pairs with a recomp
call into the canonical (and vice versa) instead of scoring as a mismatch.
"""

import logging
from typing import Iterable

from reccmp.formats.textfile import TextFile

logger = logging.getLogger(__name__)

_MAX_CANONICAL_HOPS = 8


def parse_equivalence_groups(files: Iterable[TextFile]) -> dict[int, int]:
    """member orig address -> canonical orig address, from pipe-separated files.

    Chained rows (a->b, b->c) are flattened so every member maps to the final
    canonical. Malformed lines are logged and skipped.
    """
    groups: dict[int, int] = {}
    for file in files:
        for lineno, line in enumerate(file.text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 2:
                logger.warning(
                    "%s:%d: equivalence-groups line needs at least 2 "
                    "pipe-separated fields",
                    file.path,
                    lineno,
                )
                continue
            try:
                member = int(parts[0], 16)
                canonical = int(parts[1], 16)
            except ValueError:
                logger.warning(
                    "%s:%d: unparsable equivalence-groups addresses",
                    file.path,
                    lineno,
                )
                continue
            if member == canonical:
                logger.warning(
                    "%s:%d: member equals canonical (0x%x)", file.path, lineno, member
                )
                continue
            if member in groups and groups[member] != canonical:
                logger.warning(
                    "%s:%d: conflicting canonical for member 0x%x "
                    "(0x%x vs 0x%x); keeping the first",
                    file.path,
                    lineno,
                    member,
                    groups[member],
                    canonical,
                )
                continue
            groups[member] = canonical

    # Flatten chains so canonical_orig_addr is a single dict lookup.
    for member in list(groups):
        canonical = groups[member]
        for _ in range(_MAX_CANONICAL_HOPS):
            nxt = groups.get(canonical)
            if nxt is None or nxt == canonical:
                break
            canonical = nxt
        groups[member] = canonical

    return groups


def canonical_orig_addr(groups: dict[int, int], addr: int) -> int:
    """The canonical original address for addr (itself when not a member)."""
    return groups.get(addr, addr)
