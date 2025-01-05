"""Types for the configuration of a reccmp project"""

from pathlib import Path
from dataclasses import dataclass

from pydantic import AliasChoices, BaseModel, Field


class GhidraConfig(BaseModel):
    ignore_types: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-types", "ignore_types"),
    )
    ignore_functions: list[int] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-functions", "ignore_functions"),
    )

    @classmethod
    def default(cls) -> "GhidraConfig":
        return cls(ignore_types=[], ignore_functions=[])


@dataclass
class RecCmpTarget:
    """Partial information for a target (binary file) in the decomp project
    This contains only the static information (same for all users).
    Saved to project.yml. (See ProjectFileTarget)"""

    # Unique ID for grouping the metadata.
    # If none is given we will use the base filename minus the file extension.
    target_id: str | None

    # Base filename (not a path) of the binary for this target.
    # "reccmp-project detect" uses this to search for the original and recompiled binaries
    # when creating the user.yml file.
    filename: str

    # Relative (to project root) directory of source code files for this target.
    source_root: Path

    # Ghidra-specific options for this target.
    ghidra_config: GhidraConfig


@dataclass
class RecCmpBuiltTarget(RecCmpTarget):
    """Full information for a target. Used to load component files for reccmp analysis."""

    original_path: Path
    recompiled_path: Path
    recompiled_pdb: Path


class Hash(BaseModel):
    sha256: str


class ProjectFileTarget(BaseModel):
    """Target schema for project.yml"""

    filename: str
    source_root: Path = Field(
        validation_alias=AliasChoices("source-root", "source_root")
    )
    hash: Hash
    ghidra: GhidraConfig = Field(default_factory=GhidraConfig.default)


class ProjectFile(BaseModel):
    """File schema for project.yml"""

    targets: dict[str, ProjectFileTarget]


class UserFileTarget(BaseModel):
    """Target schema for user.yml"""

    path: Path


class UserFile(BaseModel):
    """File schema for user.yml"""

    targets: dict[str, UserFileTarget]


class BuildFileTarget(BaseModel):
    """Target schema for build.yml"""

    path: Path
    pdb: Path


class BuildFile(BaseModel):
    """File schema for build.yml"""

    project: Path
    targets: dict[str, BuildFileTarget]
