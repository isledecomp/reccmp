import subprocess
import sys
import time
from reccmp.project.detect import RecCmpProject, RecCmpTarget
from .client import DaemonClient, DaemonError, DaemonUnreachable
from .registry import find_daemon, read_daemon_registry, register_daemon

__all__ = [
    "DaemonClient",
    "DaemonError",
    "DaemonUnreachable",
    "find_daemon",
    "read_daemon_registry",
    "register_daemon",
    "start_daemon_background",
]


def start_daemon_background(
    project: RecCmpProject,
    target: RecCmpTarget,
    port: int | None = None,
) -> DaemonClient | None:
    """Start a daemon for the target in a new process and wait for it to register.
    If the port is given, the daemon will try to bind to that port."""
    command = [
        sys.executable,
        "-m",
        "reccmp.tools.daemon",
        "start",
        "--foreground",
        "--target",
        target.target_id,
    ]

    if port is not None:
        command += ["--port", str(port)]

    creationflags = 0
    if sys.platform == "win32":
        creationflags = (
            subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        )

    # pylint:disable=consider-using-with
    daemon = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
        start_new_session=True,
    )

    # Wait for the daemon to register.
    for _ in range(20):
        client = find_daemon(project, target)
        if client is not None:
            return client

        # None means the process is running, which we want.
        if daemon.poll() is not None:
            return None

        time.sleep(0.5)

    return None
