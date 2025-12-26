import argparse
from contextlib import contextmanager
import logging
from pathlib import PurePosixPath
import sys
import tempfile

from pyghidra import HeadlessPyGhidraLauncher  # type: ignore[import-untyped]

from reccmp.ghidra.cli import RemoteProjectConfig, parse_reccmp_import_args
from reccmp.project.detect import argparse_parse_project_target
from reccmp.project.error import RecCmpProjectException

# Suppress linter warnings related to the fact that the header support for Ghidra is limited
# and that we cannot import Ghidra classes before Ghidra has been loaded

# pylint: disable=import-outside-toplevel
# pyright: reportMissingModuleSource=false

TEMP_PROJECT_NAME = "temp-reccmp-import"
# This name is irrelevant, but we have to pick something
TRANSACTION_NAME = "pyghidra-reccmp-import"

logger = logging.getLogger(__file__)


def main():
    args = parse_reccmp_import_args()

    try:
        target = argparse_parse_project_target(args)
    except RecCmpProjectException as e:
        logger.error("%s", e.args[0])
        return 1

    logger.info("Starting Ghidra in headless mode...")

    HeadlessPyGhidraLauncher().start()

    logger.info("Ghidra started.")

    if args.remote_url is not None:
        program_context = shared_repository_program
    else:
        program_context = local_program

    with program_context(args) as program:
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.app.script import GhidraScriptUtil
        from reccmp.ghidra.importer.importer import import_target_into_ghidra

        logger.info("Program opened. Starting reccmp import...")

        program_hash = program.getExecutableSHA256()
        # If Ghidra's hash does not match the reccmp target hash, abort
        # the import unless the user has enabled `allow-hash-mismatch`.
        if target.sha256 != program_hash:
            hash_mismatch_log_level = (
                logging.WARNING
                if target.ghidra_config.allow_hash_mismatch
                else logging.CRITICAL
            )
            logger.log(
                hash_mismatch_log_level,
                "The program hashes mismatch (Ghidra: '%s', reccmp project: '%s')",
                program_hash,
                target.sha256,
            )

            if not target.ghidra_config.allow_hash_mismatch:
                return 1

        # Not exactly sure why this is necessary, but it can't hurt
        GhidraScriptUtil.acquireBundleHostReference()

        transaction = program.startTransaction(TRANSACTION_NAME)
        api = FlatProgramAPI(program)
        import_target_into_ghidra(target, api)

        commit = True
        program.endTransaction(transaction, commit)

        # Not exactly sure why this is necessary, but it can't hurt
        GhidraScriptUtil.releaseBundleHostReference()

    logger.info("Done!")
    return 0


@contextmanager
def local_program(args: argparse.Namespace):
    from ghidra.framework import GenericRunInfo

    from reccmp.ghidra.importer.context import open_ghidra_project

    project_name: str = args.local_project_name
    file_in_repository = PurePosixPath(args.file)
    # Defaults to Ghidra's default project directory if omitted
    project_dir: str = args.local_project_dir or GenericRunInfo.getProjectsDirPath()
    assert project_dir is not None

    logger.info(
        "Opening local Ghidra project '%s' from '%s'", project_name, project_dir
    )

    # Based on the source code of pyghidra.open_program().
    # Not sure what the `restore_project` option does, maybe crash recovery? It does not seem to matter here.
    with open_ghidra_project(
        project_dir, project_name, restore_project=False
    ) as project:
        logger.debug("Opening program '%s' in Ghidra project", file_in_repository)
        read_only = False
        program = project.openProgram(
            str(file_in_repository.parent), file_in_repository.name, read_only
        )

        yield program

        # Note that `program.save()` is wrong and does not work.
        project.save(program)


@contextmanager
def shared_repository_program(args: argparse.Namespace):
    """The code is partially inspired by `HeadlessAnalyzer.java` from Ghidra."""

    # pylint:disable-next=import-error
    from java.lang import Object  # type: ignore[import-not-found]
    from ghidra.base.project import GhidraProject
    from ghidra.framework.client import ClientUtil, PasswordClientAuthenticator
    from ghidra.program.model.listing import Program
    from ghidra.util.task import TaskMonitor
    from ghidra.framework.data import DefaultCheckinHandler

    from reccmp.ghidra.importer.context import (
        create_ghidra_project,
        open_ghidra_project,
    )

    project_config = args.remote_url
    assert isinstance(project_config, RemoteProjectConfig)
    file_in_repository = args.file
    checkin_comment = args.remote_checkin_comment

    # Do NOT log the username or password for security reasons (e.g. CI use)!
    logger.info(
        "Opening remote Ghidra project '%s' at '%s:%s'",
        project_config.repository_name,
        project_config.hostname,
        project_config.port,
    )

    # The user and password must be set up before attempting to connect
    authenticator = PasswordClientAuthenticator(
        project_config.username, project_config.password
    )
    ClientUtil.setClientAuthenticator(authenticator)

    create_if_needed = False
    init_adapter = GhidraProject.getServerRepository(
        project_config.hostname,
        project_config.port,
        project_config.repository_name,
        create_if_needed,
    )
    if init_adapter is None:
        raise ConnectionError(
            f"Connection or authentication at '{project_config.hostname}' failed"
        )

    with tempfile.TemporaryDirectory() as tmp_dir:
        logger.debug("created temporary directory: %s", tmp_dir)

        # Set up a shared (remote) project.
        # I have not found an easier way to do this, partly because some constructors are private
        # and there is limited support for Java inheritance in `pyghidra` as of 2025-09.
        # Therefore, the pattern used in `HeadlessAnalyzer.java` cannot be applied.

        # We use a context because we need to make sure the project is always closed, else auto-deleting `tmp_dir` will fail.
        with create_ghidra_project(
            tmp_dir, TEMP_PROJECT_NAME, temporary=False
        ) as init_project:
            # According to the documentation, the project should be closed and re-opened
            # after a call to `convertProjectToShared()`.
            init_project.getProjectData().convertProjectToShared(
                init_adapter, TaskMonitor.DUMMY
            )

        # We use a context because we need to make sure the project is always closed, else auto-deleting `tmp_dir` will fail.
        # Not sure what the `restore_project` option does, maybe crash recovery? It does not seem to matter here.
        with open_ghidra_project(
            tmp_dir, TEMP_PROJECT_NAME, restore_project=False
        ) as project:
            logger.debug("Opening program '%s' in Ghidra project", file_in_repository)
            dom_file = project.getProjectData().getFile(file_in_repository)
            if dom_file is None:
                raise ValueError(
                    f"File not found in Ghidra repository: {file_in_repository}"
                )

            try:
                exclusive = False
                dom_file.checkout(exclusive, TaskMonitor.DUMMY)

                assert dom_file.isCheckedOut()

                # The object responsible for releasing `program`
                consumer = Object()
                ok_to_upgrade = True  # not sure if this matters
                ok_to_recover = False  # not sure if this matters
                program = dom_file.getDomainObject(
                    consumer, ok_to_upgrade, ok_to_recover, TaskMonitor.DUMMY
                )
                try:
                    assert isinstance(program, Program)

                    yield program

                    dom_file.save(TaskMonitor.DUMMY)
                finally:
                    program.release(consumer)

                keep_checked_out = False
                create_keep_file = False
                checkin_handler = DefaultCheckinHandler(
                    checkin_comment,
                    keep_checked_out,
                    create_keep_file,
                )

                dom_file.checkin(checkin_handler, TaskMonitor.DUMMY)

                logger.debug("DomainFile checked in successfully.")

            finally:
                if dom_file.isCheckedOut():
                    # Try to undo the checkout in order to keep the list of checkouts clean
                    keep = False
                    dom_file.undoCheckout(keep)


if __name__ == "__main__":
    sys.exit(main())
