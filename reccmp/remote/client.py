import logging
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from pydantic import TypeAdapter, ValidationError
from reccmp.project.detect import RecCmpTarget
from reccmp.report import (
    ReccmpReportEntity,
    ReccmpStatusReport,
    deserialize_reccmp_report,
)
from .shared import DaemonReady

logger = logging.getLogger()


class DaemonError(Exception):
    """The daemon did not return a result."""


class DaemonUnreachable(DaemonError):
    """The request could not reach the daemon."""


def request(
    url: str, method: str = "GET", timeout: float | None = 3
) -> tuple[int, bytes]:
    """Return the status and body of the response.
    Raises DaemonUnreachable if the server is not running."""
    try:
        # TODO: Any reason for connection delay on localhost?
        with urlopen(Request(url, method=method), timeout=timeout) as response:
            return (response.status, response.read())
    except HTTPError as e:
        return (e.code, e.read())
    except OSError as e:
        raise DaemonUnreachable(f"Could not reach {url}") from e


def daemon_get(url: str) -> tuple[int, bytes]:
    """Wait for the daemon to be ready, then return the status and body for the URL.
    Raises DaemonUnreachable if the daemon stops responding.
    Raises DaemonError with the daemon's message if the daemon had an error."""
    waited = False
    while True:
        # No timeout: the daemon may take a long time to build a report.
        # A daemon that is not running refuses the connection right away.
        status, body = request(url, timeout=None)

        if status in (200, 404):
            return (status, body)

        if status == 500:
            raise DaemonError(body.decode("utf-8", errors="replace"))

        if not waited:
            waited = True
            logger.info("Waiting for server...")

        time.sleep(1)


class DaemonClient:
    base_url: str

    def __init__(self, *, port: int, host: str = "127.0.0.1") -> None:
        self.base_url = f"http://{host}:{port}"

    def is_running(self, target: RecCmpTarget) -> bool:
        """Test whether the daemon for this build of the target is active."""
        try:
            status, body = request(f"{self.base_url}/ready")
        except DaemonUnreachable:
            return False

        if status != 200:
            return False

        try:
            ready = DaemonReady.model_validate_json(body)
        except ValidationError:
            return False

        # Check the build too: the port may now belong to a daemon from another build directory.
        return (
            ready.target == target.target_id
            and ready.recompiled.resolve() == target.recompiled_path.resolve()
        )

    def stop_server(self):
        try:
            request(f"{self.base_url}/stop", method="POST")
        except DaemonUnreachable:
            # Server is not running.
            return

        print("Stopping server.")

        # Wait for the server to exit so we don't connect to it again.
        for _ in range(10):
            try:
                request(f"{self.base_url}/ready")
            except DaemonUnreachable:
                return

            time.sleep(0.5)

    def get_report(
        self, diffs: bool = False, library: bool = True
    ) -> ReccmpStatusReport:
        query = urlencode({"diffs": int(diffs), "library": int(library)})
        status, body = daemon_get(f"{self.base_url}/report?{query}")
        if status != 200:
            raise DaemonError(f"Unexpected status {status} for report")

        return deserialize_reccmp_report(body.decode("utf-8"))

    def get_match(self, addr: int) -> ReccmpReportEntity | None:
        status, body = daemon_get(f"{self.base_url}/addr/{addr}")
        if status == 404:
            return None

        return TypeAdapter(ReccmpReportEntity).validate_json(body)
