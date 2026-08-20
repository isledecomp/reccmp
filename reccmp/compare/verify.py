"""Part of the core analysis/comparison logic of `reccmp`.
These functions report problems with the current entities that limit or block further analysis.
"""

import logging
from reccmp.types import EntityType, ImageId
from .db import EntityDb

logger = logging.getLogger(__name__)


def check_vtables(db: EntityDb):
    """Alert to vtable size information that cannot be correct.

    A size difference between the two vtables is not reported here: it shows up
    in the regular vtable comparison output. The one thing worth flagging ahead
    of that comparison is an impossible input: a supplied orig vtable size that
    runs into the next entity cannot be correct, and points at a problem with
    the data source rather than a real size difference.
    """
    for match in db.get_matches_by_type(EntityType.VTABLE):
        assert match.name is not None

        orig_size = match.size(ImageId.ORIG)
        if orig_size is None:
            continue

        orig_max = match.max_size(ImageId.ORIG)
        if orig_max is not None and orig_max < orig_size:
            logger.warning(
                "Orig vtable size for %s overruns the next entity", match.name
            )
