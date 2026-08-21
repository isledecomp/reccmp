import argparse
import os
import re
from typing import NamedTuple, Sequence
import urllib.parse
import logging

from reccmp.project.detect import argparse_add_project_target_args
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging

logger = logging.getLogger(__file__)


class RemoteProjectConfig(NamedTuple):
    username: str
    password: str
    hostname: str
    port: int
    repository_name: str


class RemoteProjectAction(argparse.Action):
    GHIDRA_USER_ENV_VAR = "RECCMP_GHIDRA_USER"
    GHIDRA_PASSWORD_ENV_VAR = "RECCMP_GHIDRA_PASSWORD"

    EXAMPLE_URL = "ghidra://[user:password@]localhost/repo"
    DEFAULT_PORT = 13100
    PATH_REGEX = re.compile(r"/(?P<repo>[^/]+)")

    HELP = (
        f"The URL of the remote Ghidra repository, e.g. '{EXAMPLE_URL}'. "
        + f"It is recommended to provide the username and password using the environment variables '{GHIDRA_USER_ENV_VAR}' and '{GHIDRA_PASSWORD_ENV_VAR}'."
    )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Sequence[str] | None,
        option_string=None,
    ):
        assert isinstance(values, str)
        # Ghidra's own URL handler is not a good fit because it does not support username and password,
        # so we'd have to extract those and re-assemble the URL with those removed.
        parsed_url = urllib.parse.urlparse(values)

        if parsed_url.scheme != "ghidra":
            parser.error(f"URL scheme must be 'ghidra', e.g. '{self.EXAMPLE_URL}'")

        username = (
            parsed_url.username
            or os.environ.get(self.GHIDRA_USER_ENV_VAR, None)
            or parser.error(
                f"Username must be specified via environment variable '{self.GHIDRA_USER_ENV_VAR}' or URL"
            )
        )

        if (password := parsed_url.password) is None:
            password = os.environ.get(
                self.GHIDRA_PASSWORD_ENV_VAR, None
            ) or parser.error(
                f"Password must be specified via environment variable '{self.GHIDRA_PASSWORD_ENV_VAR}' or via URL"
            )
        else:
            logger.warning(
                "CAUTION: You have provided a password on the console. Make sure this is safe. "
                + "It may be preferable to provide the password via the environment variable '%s'",
                self.GHIDRA_PASSWORD_ENV_VAR,
            )

        hostname = parsed_url.hostname or parser.error(
            f"Host must be specified in URL, e.g. '{self.EXAMPLE_URL}'"
        )
        port = parsed_url.port or self.DEFAULT_PORT

        matched_path = self.PATH_REGEX.fullmatch(parsed_url.path) or parser.error(
            f"URL must contain a repository but no further path, e.g. '{self.EXAMPLE_URL}'"
        )

        repo_name = matched_path.group("repo")

        result = RemoteProjectConfig(username, password, hostname, port, repo_name)
        setattr(namespace, self.dest, result)


def parse_reccmp_import_args():
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Recompilation Compare Ghidra Import: Import the matched entities into Ghidra.",
    )

    argparse_add_project_target_args(parser)

    # These arguments decide if this is a local or remote project
    local_or_remote = parser.add_mutually_exclusive_group(required=True)
    local_or_remote.add_argument("--local-project-name", metavar="<name>")
    local_or_remote.add_argument(
        "--remote-url",
        metavar="<url>",
        action=RemoteProjectAction,
        help=RemoteProjectAction.HELP,
    )

    # Applies to both local and remote projects
    parser.add_argument(
        "--file",
        required=True,
        metavar="<path>",
        help="The file inside the Ghidra project, e.g. '/some-dir/some-file.exe'.",
        # add a leading slash if missing
        type=lambda path: path if path.startswith("/") else f"/{path}",
    )

    # Optional arguments for local projects
    parser.add_argument(
        "--local-project-dir",
        metavar="<dir>",
        help="Defaults to Ghidra's default project directory if omitted.",
    )

    # Optional arguments for remote projects
    parser.add_argument(
        "--remote-checkin-comment",
        metavar="<message>",
        default="Automatic import from reccmp",
    )

    argparse_add_logging_args(parser)

    args = parser.parse_args()

    argparse_parse_logging(args)
    return args
