#!/usr/bin/env python3

import argparse
import asyncio
import enum
import logging
from pathlib import Path
from reccmp.project.detect import RecCmpProject
from reccmp.project.logging import (
    argparse_add_logging_args,
    argparse_parse_logging,
)
from reccmp.remote import (
    find_daemon,
    read_daemon_registry,
    start_daemon_background,
)

logger = logging.getLogger(__name__)


class DaemonSubcommand(enum.Enum):
    START = enum.auto()
    STOP = enum.auto()
    LIST = enum.auto()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="web")
    subparsers = parser.add_subparsers(required=True)

    start_parser = subparsers.add_parser("start")
    start_parser.set_defaults(subcommand=DaemonSubcommand.START)

    stop_parser = subparsers.add_parser("stop")
    stop_parser.set_defaults(subcommand=DaemonSubcommand.STOP)

    list_parser = subparsers.add_parser("list")
    list_parser.set_defaults(subcommand=DaemonSubcommand.LIST)

    start_parser.add_argument(
        "--target", metavar="<target-id>", required=True, help="ID of the target"
    )
    start_parser.add_argument(
        "--port",
        type=int,
        required=False,
        default=None,
    )
    start_parser.add_argument(
        "--foreground",
        action="store_true",
        help="Run the daemon in this process instead of in the background",
    )

    stop_parser.add_argument(
        "--target", metavar="<target-id>", required=True, help="ID of the target"
    )

    argparse_add_logging_args(parser)

    args = parser.parse_args()
    argparse_parse_logging(args)

    return args


def list_daemons(project: RecCmpProject):
    for _, registry in read_daemon_registry(project):
        print(f"{registry.target}: port {registry.port}  (pid {registry.pid})")


def main():
    args = parse_args()

    project = RecCmpProject.from_directory(Path.cwd())

    if args.subcommand == DaemonSubcommand.LIST:
        list_daemons(project)
        return

    target = project.get(args.target)
    client = find_daemon(project, target)

    if args.subcommand == DaemonSubcommand.STOP:
        if client is None:
            logger.warning("No daemon is running for %s.", target.target_id)
            return

        client.stop_server()
        return

    if client is not None:
        logger.info(
            "Daemon for %s is already running at %s.", target.target_id, client.base_url
        )
        return

    if args.foreground:
        # pylint: disable-next=import-outside-toplevel
        from reccmp.remote.server import server_main

        asyncio.run(server_main(project, target, args.port or 0))
        return

    client = start_daemon_background(project, target, port=args.port)
    if client is None:
        logger.error("Could not start a daemon for %s.", target.target_id)
        return

    logger.info("Daemon for %s is running at %s.", target.target_id, client.base_url)


if __name__ == "__main__":
    main()
