# This module can only be imported when running inside a Ghidra Python runtime.

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import logging
from typing import Iterator

from ghidra.program.flatapi import FlatProgramAPI

from reccmp.compare.db import ReccmpMatch
from reccmp.types import ImageId

from .ghidra_helper import set_ghidra_label

logger = logging.getLogger(__name__)


def import_vftables_into_ghidra(
    api: FlatProgramAPI,
    vftables: Iterator[ReccmpMatch],
    *,
    image_id: ImageId = ImageId.ORIG,
):
    for vtable in vftables:
        api.getMonitor().checkCancelled()

        raw_vtable_name = vtable.name
        assert raw_vtable_name is not None
        image_address = vtable.addr(image_id)
        assert image_address is not None
        set_ghidra_label(api, image_address, raw_vtable_name)
