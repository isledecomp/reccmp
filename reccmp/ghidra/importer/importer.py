# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import re
import logging
import traceback
from typing import Callable
from functools import partial

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import AddressSet

from reccmp.compare.core import Compare
from reccmp.project.detect import RecCmpTarget
from reccmp.types import ImageId

from .exceptions import ReccmpGhidraException
from .function_importer import PdbFunctionImporter
from .globals_importer import import_global_into_ghidra
from .pdb_extraction import PdbFunction, PdbFunctionExtractor
from .type_importer import PdbTypeImporter
from .vtable_importer import import_vftables_into_ghidra
from .globals import GLOBALS
from .types import CompiledRegexReplacements

logger = logging.getLogger(__name__)


def _import_function_into_ghidra(
    api: FlatProgramAPI,
    pdb_function: PdbFunction,
    type_importer: PdbTypeImporter,
    name_substitutions: CompiledRegexReplacements,
    *,
    image_id: ImageId = ImageId.ORIG,
):
    logger.debug("Start handling function '%s'", pdb_function.match_info.best_name())

    image_address = pdb_function.match_info.addr(image_id)
    assert image_address is not None
    hex_image_address = f"{image_address:x}"

    # Find the Ghidra function at that address
    ghidra_address = api.getAddressFactory().getAddress(hex_image_address)
    # pylint: disable=possibly-used-before-assignment
    function_importer = PdbFunctionImporter.build(
        api, pdb_function, type_importer, name_substitutions
    )

    ghidra_function = api.getFunctionAt(ghidra_address)
    if ghidra_function is None:
        ghidra_function = api.createFunction(ghidra_address, "temp")
        assert (
            ghidra_function is not None
        ), f"Failed to create function at {ghidra_address}"
        logger.info("Created new function at %s", ghidra_address)

    if image_id == ImageId.RECOMP:
        function_size = pdb_function.match_info.size(image_id)
        if function_size is not None and function_size > 0:
            body = AddressSet(ghidra_address, ghidra_address.add(function_size - 1))
            if ghidra_function.getBody() != body:
                ghidra_function.setBody(body)

    if function_importer.matches_ghidra_function(ghidra_function):
        logger.info(
            "Skipping function '%s', matches already",
            function_importer.get_full_name(),
        )
        return

    logger.debug(
        "Modifying function %s at 0x%s",
        function_importer.get_full_name(),
        hex_image_address,
    )

    function_importer.overwrite_ghidra_function(ghidra_function)

    GLOBALS.statistics.functions_changed += 1


def _do_with_error_handling(step_name: str, action: Callable[[], None]):
    try:
        action()
        GLOBALS.statistics.successes += 1
    except ReccmpGhidraException as e:
        _log_and_track_failure(step_name, e)
    except RuntimeError as e:
        cause = e.args[0]
        _log_and_track_failure(step_name, cause, unexpected=True)
        logger.error(traceback.format_exc())
    except Exception as e:  # pylint: disable=broad-exception-caught
        _log_and_track_failure(step_name, e, unexpected=True)
        logger.error(traceback.format_exc())


def _do_execute_import(
    api: FlatProgramAPI,
    extraction: PdbFunctionExtractor,
    ignore_types: set[str],
    ignore_functions: set[int],
    name_substitutions: list[tuple[str, str]],
    *,
    image_id: ImageId = ImageId.ORIG,
):
    pdb_functions = extraction.get_function_list()

    # pylint: disable=possibly-used-before-assignment
    type_importer = PdbTypeImporter(api, extraction, ignore_types=ignore_types)

    logger.info("Importing globals...")
    for glob in extraction.compare.get_variables():
        api.getMonitor().checkCancelled()

        _do_with_error_handling(
            glob.name or hex(glob.orig_addr),
            partial(
                import_global_into_ghidra,
                api,
                extraction.compare,
                type_importer,
                glob,
                image_id=image_id,
            ),
        )

    logger.info("Importing functions...")
    name_substitutions_compiled = [
        (re.compile(regex), replacement) for regex, replacement in name_substitutions
    ]

    for pdb_func in pdb_functions:
        api.getMonitor().checkCancelled()

        func_name = pdb_func.match_info.name
        orig_addr = pdb_func.match_info.orig_addr
        if orig_addr in ignore_functions:
            logger.info(
                "Skipping function '%s' at '%s' because it is on the ignore list",
                func_name,
                hex(orig_addr),
            )
            continue

        _do_with_error_handling(
            func_name or hex(orig_addr),
            partial(
                _import_function_into_ghidra,
                api,
                pdb_func,
                type_importer,
                name_substitutions_compiled,
                image_id=image_id,
            ),
        )

    logger.info("Finished importing functions.")

    logger.info("Importing vftables...")
    import_vftables_into_ghidra(
        api, extraction.compare.get_vtables(), image_id=image_id
    )
    logger.info("Finished importing vftables.")


def _log_and_track_failure(
    step_name: str | None, error: Exception, unexpected: bool = False
):
    if GLOBALS.statistics.track_failure_and_tell_if_new(error):
        logger.error(
            "%s: %s%s",
            step_name,
            "Unexpected error: " if unexpected else "",
            error,
            exc_info=error,
        )


def import_target_into_ghidra(
    target: RecCmpTarget,
    api: FlatProgramAPI,
    image_id: ImageId = ImageId.ORIG,
):
    compare = Compare.from_target(target)

    # try to acquire matched functions
    extractor = PdbFunctionExtractor(compare)
    try:
        _do_execute_import(
            api,
            extractor,
            set(target.ghidra_config.ignore_types),
            set(target.ghidra_config.ignore_functions),
            target.ghidra_config.name_substitutions,
            image_id=image_id,
        )
    finally:
        GLOBALS.statistics.log()
