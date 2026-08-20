"""Part of the core analysis/comparison logic of `reccmp`.
These functions report problems with the current entities that limit or block further analysis.
"""

import logging
from reccmp.types import EntityType, ImageId
from .db import EntityDb

logger = logging.getLogger(__name__)


def check_vtables(db: EntityDb):
    """Check vtable sizes provided by the data source.

    Size differences between the orig and recomp vtables are reported by the
    vtable comparison, so they are not checked here. The only check is that a
    user-provided orig vtable size does not extend past the next entity in the
    binary. If it does, the size can't be right, so warn about it.
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
