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
# pylint: disable=undefined-variable # need to disable this one globally because pylint does not understand e.g. `currentProgram()`

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import importlib
import json
import sys
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # builtins that are available on the root level of scripts
    from ghidra.ghidra_builtins import *  # pyright: ignore[reportWildcardImportFromLibrary] # pylint: disable=wildcard-import # these are just for headers

####################################################
# Global settings for the Ghidrathon import script #
####################################################
LOG_LEVEL = logging.DEBUG
VERBOSE = False


logger = logging.getLogger(__name__)


try:
    from ghidra.program.flatapi import FlatProgramAPI
except ImportError as importError:
    logger.error(
        "Failed to import Ghidra functions. Has this script been launched from Ghidra?"
    )
    logger.debug("Precise import error:", exc_info=importError)


def add_python_path(path: Path):
    """
    Scripts in Ghidra are executed from the /reccmp/ghidra/scripts directory. We need to add
    a few more paths to the Python path so we can import the other libraries.
    """
    logger.info("Adding %s to Python Path", path)
    assert path.exists()
    sys.path.insert(1, str(path))


def get_repository_root():
    return Path(__file__).absolute().parent.parent.parent.parent


def find_and_add_venv_to_pythonpath():
    path = Path(__file__).resolve()

    # Add the virtual environment if we are in one, e.g. `.venv/Lib/site-packages/reccmp/ghidra/scripts/import_[...].py`
    while not path.is_mount():
        if path.name == "site-packages":
            add_python_path(path)
            return
        path = path.parent

    # Development setup: Running from the reccmp repository. The dependencies must be installed in a venv with name `.venv`.

    # This one is needed when the reccmp project is installed in editable mode and we are running directly from the source
    add_python_path(get_repository_root())

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


setup_logging()
find_and_add_venv_to_pythonpath()

logging.root.setLevel(LOG_LEVEL)


def find_target(api: "FlatProgramAPI") -> "RecCmpTarget":
    """
    Tries to find a `reccmp` project on a parent path of this script file.
    This can be achieved by installing `reccmp` into a venv inside a decompilation project
    and having `reccmp-build.yaml` next to the venv directory.

    Inside that `reccmp` project, a target is chosen based on the hash of the executable of the current file.

    **Known issue**: In order to use this script, `reccmp-build.yml` must be located
    in the same directory as `reccmp-project.yml`.
    """

    project_search_path = Path(__file__).parent

    try:
        project = RecCmpProject.from_directory(project_search_path)
    except RecCmpProjectNotFoundException as e:
        # Figure out if we are in a dev setup. Using this is e.g. necessary when `reccmp` is installed in editable mode
        debug_config_file = Path(__file__).parent.parent / "dev_config.json"
        if not debug_config_file.exists():
            raise e

        with debug_config_file.open() as infile:
            debug_config = json.load(infile)

        project = RecCmpProject.from_directory(Path(debug_config["projectDir"]))

    # We must have loaded a project file if we are here.
    assert project.project_config_path is not None

    # Set up logfile next to the project config file
    file_handler = logging.FileHandler(
        project.project_config_path.parent / "ghidra_import.log", mode="w"
    )
    file_handler.setFormatter(logging.root.handlers[0].formatter)
    logging.root.addHandler(file_handler)

    target_hash = api.getCurrentProgram().getExecutableSHA256()

    matching_targets = [
        target_id
        for target_id, target in project.targets.items()
        if target.sha256 == target_hash
    ]

    if not matching_targets:
        logger.error("No target with hash '%s' is configured", target_hash)
        sys.exit(1)
    elif len(matching_targets) > 1:
        logger.warning(
            "Found multiple targets with hash '%s'. Using the first one.",
            target_hash,
        )

    return project.get(matching_targets[0])


def reload_module(module: str):
    """
    Due to a quirk in Jep (used by Ghidrathon), imported modules persist for the lifetime of the Ghidra process
    and are not reloaded when relaunching the script. Therefore, in order to facilitate development
    we force reload all our own modules at startup. See also https://github.com/mandiant/Ghidrathon/issues/103.

    Note that as of 2024-05-30, this remedy does not work perfectly (yet): Some changes in decomp are
    still not detected correctly and require a Ghidra restart to be applied.
    """
    importlib.reload(importlib.import_module(module))


def main():
    api = FlatProgramAPI(currentProgram(), getMonitor())

    target = find_target(api)

    logger.info("Importing file: %s", target.original_path)

    if not VERBOSE:
        logging.getLogger("bin").setLevel(logging.WARNING)
        logging.getLogger("compare.core").setLevel(logging.WARNING)
        logging.getLogger("compare.db").setLevel(logging.WARNING)
        logging.getLogger("compare.lines").setLevel(logging.WARNING)
        logging.getLogger("cvdump.symbols").setLevel(logging.WARNING)

    import_target_into_ghidra(target, api)
    logger.info("Done!")


# sys.path is not reset after running the script, so we should restore it
sys_path_backup = sys.path.copy()
try:
    import setuptools  # type: ignore[import-untyped] # pylint: disable=unused-import # required to fix a distutils issue in Python 3.12

    # Packages are imported down here because reccmp's dependencies are only available after the venv was added to the pythonpath
    reload_module("reccmp.project.detect")
    from reccmp.project.detect import RecCmpProject, RecCmpTarget
    from reccmp.project.error import RecCmpProjectNotFoundException

    reload_module("reccmp.ghidra.importer.importer")
    from reccmp.ghidra.importer.importer import import_target_into_ghidra

    reload_module("reccmp.compare")
    reload_module("reccmp.compare.db")
    reload_module("reccmp.ghidra.importer.entity_names")
    reload_module("reccmp.ghidra.importer.exceptions")
    reload_module("reccmp.ghidra.importer.pdb_extraction")
    reload_module("reccmp.ghidra.importer.ghidra_helper")
    reload_module("reccmp.ghidra.importer.vtable_importer")
    reload_module("reccmp.ghidra.importer.globals_importer")
    reload_module("reccmp.ghidra.importer.function_importer")
    reload_module("reccmp.ghidra.importer.type_importer")
    reload_module("reccmp.ghidra.importer.statistics")
    reload_module("reccmp.ghidra.importer.globals")

    if __name__ == "__main__":
        main()
finally:
    sys.path = sys_path_backup
