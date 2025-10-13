"""Part of the core analysis/comparison logic of `reccmp`.
These functions report problems with the current entities that limit or block further analysis.
"""

import logging
import struct
from reccmp.isledecomp.formats.pe import PEImage
from reccmp.isledecomp.types import EntityType
from .db import EntityDb


logger = logging.getLogger(__name__)


def check_vtables(db: EntityDb, orig_bin: PEImage):
    """Alert to cases where the recomp vtable is larger than the one in the orig binary.
    We can tell by looking at:
    1. The address of the following vtable in orig, which gives an upper bound on the size.
    2. The pointers in the orig vtable. If any are zero bytes, this is alignment padding between two vtables.
    """
    for match in db.get_matches_by_type(EntityType.VTABLE):
        assert (
            match.name is not None
            and match.orig_addr is not None
            and match.recomp_addr is not None
            and match.size is not None
        )

        next_orig = db.get_next_orig_addr(match.orig_addr)
        if next_orig is None:
            # this vtable is the last annotation in the project
            continue

        orig_size_upper_limit = next_orig - match.orig_addr
        if orig_size_upper_limit < match.size:
            logger.warning(
                "Recomp vtable is larger than orig vtable for %s",
                match.name,
            )
            continue

        # TODO: We might want to fix this at the source (cvdump) instead.
        # Any problem will be logged later when we compare the vtable.
        vtable_size = 4 * (min(match.size, orig_size_upper_limit) // 4)
        orig_table = orig_bin.read(match.orig_addr, vtable_size)

        # Check for a gap (null pointer) in the orig vtable.
        # This may or may not be present, but if it is there, we know the vtable
        # on the recomp side is larger.
        if any(addr == 0 for addr, in struct.iter_unpack("<L", orig_table)):
            logger.warning(
                "Recomp vtable is larger than orig vtable for %s", match.name
            )
