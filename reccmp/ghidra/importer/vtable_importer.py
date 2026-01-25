# This file can only be imported successfully when run from Ghidra using Ghidrathon.

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import logging
from typing import Iterator

from ghidra.program.flatapi import FlatProgramAPI

from reccmp.decomp.compare.db import ReccmpMatch

from .ghidra_helper import set_ghidra_label


logger = logging.getLogger(__name__)


def import_vftables_into_ghidra(api: FlatProgramAPI, vftables: Iterator[ReccmpMatch]):
    for vtable in vftables:
        api.getMonitor().checkCancelled()

        raw_vtable_name = vtable.name
        assert raw_vtable_name is not None
        set_ghidra_label(api, vtable.orig_addr, raw_vtable_name)
