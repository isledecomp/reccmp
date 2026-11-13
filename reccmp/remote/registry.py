import os
from pathlib import Path
from pydantic import BaseModel, ValidationError
from reccmp.project.detect import RecCmpProject, RecCmpTarget
from .client import DaemonClient


class DaemonRegistry(BaseModel):
    target: str
    port: int
    pid: int


def _get_build_directory(project: RecCmpProject) -> Path:
    assert project.build_config_path is not None
    return project.build_config_path.parent


def _get_registry_path(project: RecCmpProject, port: int) -> Path:
    return _get_build_directory(project) / f"reccmp-daemon-{port}.json"


def _get_registry_files_for_project(project: RecCmpProject) -> list[Path]:
    return sorted(_get_build_directory(project).glob("reccmp-daemon-*.json"))


def register_daemon(project: RecCmpProject, target_id: str, port: int) -> Path:
    """Create the registry file for the daemon we just started."""
    registry = DaemonRegistry(target=target_id, port=port, pid=os.getpid())
    path = _get_registry_path(project, port)
    path.write_text(registry.model_dump_json(), encoding="utf-8")
    return path


def read_daemon_registry(project: RecCmpProject) -> list[tuple[Path, DaemonRegistry]]:
    """Read all daemon registry files for this reccmp project."""
    registry = []
    for path in _get_registry_files_for_project(project):
        try:
            text = path.read_text(encoding="utf-8")
            registry.append((path, DaemonRegistry.model_validate_json(text)))
        except (OSError, ValidationError):
            continue

    return registry


def find_daemon(project: RecCmpProject, target: RecCmpTarget) -> DaemonClient | None:
    """If there is a daemon running for the given target, provide its connection interface."""
    for path, registry in read_daemon_registry(project):
        if registry.target != target.target_id:
            continue

        client = DaemonClient(port=registry.port)
        if client.is_running(target):
            return client

        # The daemon for this registry file is not running. Delete it.
        path.unlink(missing_ok=True)

    return None
