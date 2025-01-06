# This file can only be imported successfully when run from Ghidra using Ghidrathon.

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import logging
from typing import Iterator

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType

from reccmp.isledecomp.compare.db import ReccmpEntity

from .ghidra_helper import get_namespace_and_name


logger = logging.getLogger(__name__)


def import_vftables_into_ghidra(api: FlatProgramAPI, vftables: Iterator[ReccmpEntity]):
    address_factory = api.getAddressFactory()
    symbol_table = api.getCurrentProgram().getSymbolTable()
    for vtable in vftables:
        raw_vtable_name = vtable.name
        assert raw_vtable_name is not None
        namespace, name = get_namespace_and_name(api, raw_vtable_name)

        address_hex = f"{vtable.orig_addr:x}"
        address_ghidra = address_factory.getAddress(address_hex)

        existing_label = symbol_table.getPrimarySymbol(address_ghidra)
        if existing_label is not None:
            existing_label_name = existing_label.getName()
            if (
                existing_label.getParentNamespace() == namespace
                and existing_label_name == name
            ):
                logger.debug(
                    "Label '%s' at 0x%s already exists", raw_vtable_name, address_hex
                )
            else:
                logger.debug(
                    "Changing label at 0x%s from '%s' to '%s'",
                    address_hex,
                    existing_label_name,
                    raw_vtable_name,
                )
                existing_label.setNameAndNamespace(
                    name, namespace, SourceType.USER_DEFINED
                )
        else:
            logger.debug("Adding label '%s' at 0x%s", name, address_hex)
            symbol_table.createLabel(address_ghidra, name, SourceType.USER_DEFINED)
