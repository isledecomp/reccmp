from contextlib import contextmanager

from ghidra.base.project import GhidraProject

# pyright: reportMissingModuleSource=false


@contextmanager
def create_ghidra_project(project_dir_path: str, project_name: str, temporary: bool):
    """A context manager for `ghidra.base.project.GhidraProject.createProject()` that automatically closes the project."""
    project = GhidraProject.createProject(project_dir_path, project_name, temporary)
    try:
        yield project
    finally:
        project.getProject().close()


@contextmanager
def open_ghidra_project(
    project_dir_path: str, project_name: str, restore_project: bool
):
    """A context manager for `ghidra.base.project.GhidraProject.openProject()` that automatically closes the project."""
    project = GhidraProject.openProject(project_dir_path, project_name, restore_project)
    try:
        yield project
    finally:
        project.getProject().close()
