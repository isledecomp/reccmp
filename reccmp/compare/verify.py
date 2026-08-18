"""Part of the core analysis/comparison logic of `reccmp`.
These functions report problems with the current entities that limit or block further analysis.
"""

import logging
import struct
from reccmp.formats.pe import PEImage
from reccmp.types import EntityType, ImageId
from .db import EntityDb

logger = logging.getLogger(__name__)


def _table_has_entries_past(image: PEImage, addr: int, start: int, end: int) -> bool:
    """Whether the vtable at `addr` has any real entry in the byte range
    [start, end). The size that produced `end` may over-count the table by a
    trailing alignment slot, so only a non-null pointer counts as an entry."""
    start = 4 * (start // 4)
    end = 4 * (end // 4)
    if end <= start:
        return False

    tail = image.read(addr + start, end - start)
    return any(addr != 0 for addr, in struct.iter_unpack("<L", tail))


def check_vtables(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    """Alert to cases where the recomp vtable is larger than the one in the orig binary.

    If a data source gives the orig vtable's true size, we can compare the two
    tables directly. Otherwise the orig size is unknown and we estimate it from:
    1. The address of the following vtable in orig, which gives an upper bound on the size.
    2. The pointers in the orig vtable. If any are zero bytes, this is alignment padding between two vtables.

    Both estimates read the orig table at the *recomp* size, which is itself an
    estimate (next-symbol distance or section contribution) and may over-count
    the table by a trailing alignment slot. Reading that far into orig walks
    past the end of the real table and reports a size difference that is not
    there, so a known orig size takes priority over either estimate.

    Comparing the two sizes does not settle it either, for the same reason:
    a recomp size greater than the orig size may be nothing but that trailing
    slot. Compare the entries instead. A null pointer past the end of the orig
    table is padding; a real address is a virtual function that orig does not
    have.
    """
    for match in db.get_matches_by_type(EntityType.VTABLE):
        assert (
            match.name is not None
            and match.orig_addr is not None
            and match.recomp_addr is not None
        )

        orig_size = match.size(ImageId.ORIG)
        if orig_size is not None:
            # We know the orig size, so the estimates below do not apply.
            orig_max = match.max_size(ImageId.ORIG)
            if orig_max is not None and orig_max < orig_size:
                # Not a size difference: the orig size we were given runs into
                # the next entity, so it cannot be correct.
                logger.warning(
                    "Orig vtable size for %s overruns the next entity", match.name
                )
                continue

            if _table_has_entries_past(
                recomp_bin,
                match.recomp_addr,
                orig_size,
                match.any_size(ImageId.RECOMP),
            ):
                logger.warning(
                    "Recomp vtable is larger than orig vtable for %s",
                    match.name,
                )

            continue

        vtable_size = match.any_size(ImageId.RECOMP)

        orig_max = match.max_size(ImageId.ORIG)
        if orig_max is not None and orig_max < vtable_size:
            logger.warning(
                "Recomp vtable is larger than orig vtable for %s",
                match.name,
            )
            continue

        # TODO: We might want to fix this at the source (cvdump) instead.
        # Any problem will be logged later when we compare the vtable.
        vtable_size = 4 * (vtable_size // 4)
        orig_table = orig_bin.read(match.orig_addr, vtable_size)

        # Check for a gap (null pointer) in the orig vtable.
        # This may or may not be present, but if it is there, we know the vtable
        # on the recomp side is larger.
        if any(addr == 0 for addr, in struct.iter_unpack("<L", orig_table)):
            logger.warning(
                "Recomp vtable is larger than orig vtable for %s", match.name
            )
