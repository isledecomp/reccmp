# Imports types and function signatures from debug symbols (PDB file) of the recompilation.
#
# This script uses Python 3 and therefore requires Ghidrathon to be installed in Ghidra (see https://github.com/mandiant/Ghidrathon).
# Furthermore, the virtual environment must be set up beforehand under $REPOSITORY_ROOT/.venv, and all required packages must be installed
# (see README.md).
# Also, the Python version of the virtual environment must probably match the Python version used for Ghidrathon.

# @author J. Schulz
# @category reccmp
# @keybinding
# @menupath
# @toolbar


# In order to make this code run both within and outside of Ghidra, the import order is rather unorthodox in this file.
# That is why some of the lints below are disabled.

# pylint: disable=wrong-import-position,ungrouped-imports
# pylint: disable=undefined-variable # need to disable this one globally because pylint does not understand e.g. `askYesNo()``

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import importlib
import json
import logging.handlers
import sys
import logging
from pathlib import Path
import traceback
from typing import TYPE_CHECKING, Callable
from functools import partial

if TYPE_CHECKING:
    from reccmp.ghidra_scripts.lego_util.headers import *  # pylint: disable=wildcard-import # these are just for headers


logger = logging.getLogger(__name__)


def reload_module(module: str):
    """
    Due to a quirk in Jep (used by Ghidrathon), imported modules persist for the lifetime of the Ghidra process
    and are not reloaded when relaunching the script. Therefore, in order to facilitate development
    we force reload all our own modules at startup. See also https://github.com/mandiant/Ghidrathon/issues/103.

    Note that as of 2024-05-30, this remedy does not work perfectly (yet): Some changes in isledecomp are
    still not detected correctly and require a Ghidra restart to be applied.
    """
    importlib.reload(importlib.import_module(module))


def add_python_path(path: Path):
    """
    Scripts in Ghidra are executed from the tools/ghidra_scripts directory. We need to add
    a few more paths to the Python path so we can import the other libraries.
    """
    logger.info("Adding %s to Python Path", path)
    assert path.exists()
    sys.path.insert(1, str(path))


def find_and_add_venv_to_pythonpath():
    path = Path(__file__).resolve()

    # Add the virtual environment if we are in one, e.g. `.venv/Lib/site-packages/reccmp/ghidra_scripts/import_[...].py`
    while not path.is_mount():
        if path.name == "site-packages":
            add_python_path(path)
            return
        path = path.parent

    # Development setup: Running from the reccmp repository. The dependencies must be installed in a venv with name `.venv`.

    # This one is needed when the reccmp project is installed in editable mode and we are running directly from the source
    add_python_path(Path(__file__).parent.parent.parent)

    # Now we add the virtual environment where the dependencies need to be installed
    path = Path(__file__).resolve()
    while not path.is_mount():
        venv_candidate = path / ".venv"
        if venv_candidate.exists():
            site_packages = next(venv_candidate.glob("lib/**/site-packages/"), None)
            if site_packages is not None:
                add_python_path(site_packages)
                return
        path = path.parent

    logger.warning(
        "No virtual environment was found. This script might fail to find dependencies."
    )


def setup_logging():
    logging.root.handlers.clear()
    formatter = logging.Formatter("%(levelname)-8s %(message)s")
    # formatter = logging.Formatter("%(name)s %(levelname)-8s %(message)s") # use this to identify loggers
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    logging.root.addHandler(stdout_handler)

    logger.info("Starting import...")


# This script can be run both from Ghidra and as a standalone.
# In the latter case, only the PDB parser will be used.
setup_logging()
find_and_add_venv_to_pythonpath()
reload_module("reccmp.ghidra_scripts.lego_util.statistics")
reload_module("reccmp.ghidra_scripts.lego_util.globals")
from reccmp.ghidra_scripts.lego_util.globals import GLOBALS

logging.root.setLevel(GLOBALS.loglevel)

try:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.exception import CancelledException

    GLOBALS.running_from_ghidra = True
except ImportError as importError:
    logger.error(
        "Failed to import Ghidra functions, doing a dry run for the source code parser. "
        "Has this script been launched from Ghidra?"
    )
    logger.debug("Precise import error:", exc_info=importError)

    GLOBALS.running_from_ghidra = False
    CancelledException = None


def get_repository_root():
    return Path(__file__).absolute().parent.parent.parent


# We need to quote the types here because they might not exist when running without Ghidra
def import_function_into_ghidra(
    api: "FlatProgramAPI",
    pdb_function: "PdbFunction",
    type_importer: "PdbTypeImporter",
):
    hex_original_address = f"{pdb_function.match_info.orig_addr:x}"

    # Find the Ghidra function at that address
    ghidra_address = getAddressFactory().getAddress(hex_original_address)
    # pylint: disable=possibly-used-before-assignment
    function_importer = PdbFunctionImporter.build(api, pdb_function, type_importer)

    ghidra_function = getFunctionAt(ghidra_address)
    if ghidra_function is None:
        ghidra_function = createFunction(ghidra_address, "temp")
        assert (
            ghidra_function is not None
        ), f"Failed to create function at {ghidra_address}"
        logger.info("Created new function at %s", ghidra_address)

    logger.debug("Start handling function '%s'", function_importer.get_full_name())

    if function_importer.matches_ghidra_function(ghidra_function):
        logger.info(
            "Skipping function '%s', matches already",
            function_importer.get_full_name(),
        )
        return

    logger.debug(
        "Modifying function %s at 0x%s",
        function_importer.get_full_name(),
        hex_original_address,
    )

    function_importer.overwrite_ghidra_function(ghidra_function)

    GLOBALS.statistics.functions_changed += 1


def do_with_error_handling(step_name: str, action: Callable[[], None]):
    try:
        action()
        GLOBALS.statistics.successes += 1
    except Lego1Exception as e:
        log_and_track_failure(step_name, e)
    except RuntimeError as e:
        cause = e.args[0]
        if CancelledException is not None and isinstance(cause, CancelledException):
            # let Ghidra's CancelledException pass through
            logging.critical("Import aborted by the user.")
            return

        log_and_track_failure(step_name, cause, unexpected=True)
        logger.error(traceback.format_exc())
    except Exception as e:  # pylint: disable=broad-exception-caught
        log_and_track_failure(step_name, e, unexpected=True)
        logger.error(traceback.format_exc())


def do_execute_import(
    extraction: "PdbFunctionExtractor",
    ignore_types: set[str],
    ignore_functions: set[int],
):
    pdb_functions = extraction.get_function_list()

    if not GLOBALS.running_from_ghidra:
        logger.info("Completed the dry run outside Ghidra.")
        return

    api = FlatProgramAPI(currentProgram())

    # pylint: disable=possibly-used-before-assignment
    type_importer = PdbTypeImporter(api, extraction, ignore_types=ignore_types)

    logger.info("Importing globals...")
    for glob in extraction.compare.get_variables():
        do_with_error_handling(
            glob.name or hex(glob.orig_addr),
            partial(
                import_global_into_ghidra, api, extraction.compare, type_importer, glob
            ),
        )

    logger.info("Importing functions...")
    for pdb_func in pdb_functions:
        func_name = pdb_func.match_info.name
        orig_addr = pdb_func.match_info.orig_addr
        if orig_addr in ignore_functions:
            logger.info(
                "Skipping function '%s' at '%s' because it is on the ignore list",
                func_name,
                hex(orig_addr),
            )
            continue

        do_with_error_handling(
            func_name or hex(orig_addr),
            partial(import_function_into_ghidra, api, pdb_func, type_importer),
        )

    logger.info("Finished importing functions.")

    logger.info("Importing vftables...")
    import_vftables_into_ghidra(api, extraction.compare.get_vtables())
    logger.info("Finished importing vftables.")


def log_and_track_failure(
    step_name: str | None, error: Exception, unexpected: bool = False
):
    if GLOBALS.statistics.track_failure_and_tell_if_new(error):
        logger.error(
            "%s: %s%s",
            step_name,
            "Unexpected error: " if unexpected else "",
            error,
        )


def find_target() -> "RecCmpTarget":
    """
    Known issue: In order to use this script, `reccmp-build.yml` must be located in the same directory as `reccmp-project.yml`.
    """

    project_search_path = Path(__file__).parent

    try:
        project = RecCmpProject.from_directory(project_search_path)
    except RecCmpProjectNotFoundException as e:
        # Figure out if we are in a debugging scenario
        debug_config_file = Path(__file__).parent / "dev_config.json"
        if not debug_config_file.exists():
            raise RecCmpProjectNotFoundException(
                f"Cannot find a reccmp project under {project_search_path} (missing {RECCMP_PROJECT_CONFIG}/{RECCMP_BUILD_CONFIG})"
            ) from e

        with debug_config_file.open() as infile:
            debug_config = json.load(infile)

        project = RecCmpProject.from_directory(Path(debug_config["projectDir"]))

    # We must have loaded a project file if we are here.
    assert project.project_config_path is not None

    # Set up logfile next to the project config file
    file_handler = logging.FileHandler(
        project.project_config_path.parent.joinpath("ghidra_import.log"), mode="w"
    )
    file_handler.setFormatter(logging.root.handlers[0].formatter)
    logging.root.addHandler(file_handler)

    if GLOBALS.running_from_ghidra:
        GLOBALS.target_name = getProgramFile().getName()

    matching_targets = [
        target_id
        for target_id, target in project.targets.items()
        if target.filename == GLOBALS.target_name
    ]

    if not matching_targets:
        logger.error("No target with file name '%s' is configured", GLOBALS.target_name)
        sys.exit(1)
    elif len(matching_targets) > 1:
        logger.warning(
            "Found multiple targets for file name '%s'. Using the first one.",
            GLOBALS.target_name,
        )

    return project.get(matching_targets[0])


def main():
    target = find_target()

    logger.info("Importing file: %s", target.original_path)

    if not GLOBALS.verbose:
        logging.getLogger("isledecomp.bin").setLevel(logging.WARNING)
        logging.getLogger("isledecomp.compare.core").setLevel(logging.WARNING)
        logging.getLogger("isledecomp.compare.db").setLevel(logging.WARNING)
        logging.getLogger("isledecomp.compare.lines").setLevel(logging.WARNING)
        logging.getLogger("isledecomp.cvdump.symbols").setLevel(logging.WARNING)

    logger.info("Starting comparison")
    isle_compare = IsleCompare.from_target(target)
    logger.info("Comparison complete.")

    # try to acquire matched functions
    extractor = PdbFunctionExtractor(isle_compare)
    try:
        do_execute_import(
            extractor,
            set(target.ghidra_config.ignore_types),
            set(target.ghidra_config.ignore_functions),
        )
    finally:
        if GLOBALS.running_from_ghidra:
            GLOBALS.statistics.log()

        logger.info("Done")


# sys.path is not reset after running the script, so we should restore it
sys_path_backup = sys.path.copy()
try:
    import setuptools  # type: ignore[import-untyped] # pylint: disable=unused-import # required to fix a distutils issue in Python 3.12

    # Packages are imported down here because reccmp's dependencies are only available after the venv was added to the pythonpath
    reload_module("reccmp.project.detect")
    from reccmp.project.common import RECCMP_BUILD_CONFIG, RECCMP_PROJECT_CONFIG
    from reccmp.project.detect import RecCmpProject, RecCmpTarget
    from reccmp.project.error import RecCmpProjectNotFoundException

    reload_module("reccmp.isledecomp.compare")
    from reccmp.isledecomp.compare import Compare as IsleCompare

    reload_module("reccmp.isledecomp.compare.db")

    reload_module("reccmp.ghidra_scripts.lego_util.exceptions")
    from reccmp.ghidra_scripts.lego_util.exceptions import Lego1Exception

    reload_module("reccmp.ghidra_scripts.lego_util.pdb_extraction")
    from reccmp.ghidra_scripts.lego_util.pdb_extraction import (
        PdbFunctionExtractor,
        PdbFunction,
    )

    if GLOBALS.running_from_ghidra:
        reload_module("reccmp.ghidra_scripts.lego_util.ghidra_helper")

        reload_module("reccmp.ghidra_scripts.lego_util.vtable_importer")
        from reccmp.ghidra_scripts.lego_util.vtable_importer import (
            import_vftables_into_ghidra,
        )

        reload_module("reccmp.ghidra_scripts.lego_util.globals_importer")
        from reccmp.ghidra_scripts.lego_util.globals_importer import (
            import_global_into_ghidra,
        )

        reload_module("reccmp.ghidra_scripts.lego_util.function_importer")
        from reccmp.ghidra_scripts.lego_util.function_importer import (
            PdbFunctionImporter,
        )

        reload_module("reccmp.ghidra_scripts.lego_util.type_importer")
        from reccmp.ghidra_scripts.lego_util.type_importer import PdbTypeImporter

    if __name__ == "__main__":
        main()
finally:
    sys.path = sys_path_backup
