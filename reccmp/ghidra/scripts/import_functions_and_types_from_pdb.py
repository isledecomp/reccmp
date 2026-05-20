# Imports types and function signatures from debug symbols (PDB file) of the recompilation.
#
# This script uses Python 3 and therefore requires Ghidra to be launched with pyghidra enabled.
# Furthermore, the virtual environment must be set up beforehand under $REPOSITORY_ROOT/.venv, and all required packages must be installed
# (see README.md).

# @author The reccmp Dev Team
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

##########################################
# Global settings for this import script #
##########################################
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


def reload_reccmp_modules():
    """
    As of 2026-05 (Ghidra 12.1), imported modules persist for the lifetime of the Ghidra process
    and are not reloaded when relaunching the script. Therefore, in order to facilitate development
    we forcibly reload all of reccmp's modules at startup.

    **NOTE**: One reload turns out to be insufficient to update most modules. A few spot-checks
    did not reveal any modules that require more than two reloads, but there is a chance that two reloads
    is not enough everywhere. If you run into issues, please increase the number and document which module was affected.
    """

    num_reloads = 2

    for _ in range(num_reloads):
        # needed because sys.modules is changed by importlib.reload()
        loaded_modules = sys.modules.copy()

        for name, module in loaded_modules.items():
            if "reccmp" in name:
                importlib.reload(module)


def main():
    api = FlatProgramAPI(getCurrentProgram(), getMonitor())

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
    reload_reccmp_modules()

    # Packages are imported down here because reccmp's dependencies are only available after the venv was added to the pythonpath
    from reccmp.project.detect import RecCmpProject, RecCmpTarget
    from reccmp.project.error import RecCmpProjectNotFoundException
    from reccmp.ghidra.importer.importer import import_target_into_ghidra

    if __name__ == "__main__":
        main()
finally:
    sys.path = sys_path_backup
