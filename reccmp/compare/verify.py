"""Part of the core analysis/comparison logic of `reccmp`.
These functions report problems with the current entities that limit or block further analysis.
"""

import logging
import struct
from reccmp.formats.pe import PEImage
from reccmp.types import EntityType, ImageId
from .db import EntityDb

logger = logging.getLogger(__name__)


def check_vtables(db: EntityDb, orig_bin: PEImage):
    """Alert to cases where the recomp vtable is larger than the one in the orig binary.
    We can tell by looking at:
    1. The address of the following vtable in orig, which gives an upper bound on the size.
    2. The pointers in the orig vtable. If any are zero bytes, this is alignment padding between two vtables.
    A data source can supply the orig vtable's true size. When present it takes
    priority over the recomp size, which is an estimate (next-symbol distance or
    section contribution) that may include trailing alignment padding.
    """
    for match in db.get_matches_by_type(EntityType.VTABLE):
        assert (
            match.name is not None
            and match.orig_addr is not None
            and match.recomp_addr is not None
        )

        vtable_size = match.any_size(ImageId.ORIG)

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
