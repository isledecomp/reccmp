"""Types for the configuration of a reccmp project"""

from pathlib import Path
from dataclasses import dataclass

from pydantic import AliasChoices, BaseModel, Field


class GhidraConfig(BaseModel):
    """Ghidra-specific settings"""

    ignore_types: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-types", "ignore_types"),
        description="Names of types to ignore",
    )
    ignore_functions: list[int] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-functions", "ignore_functions"),
        description="Addresses of functions to ignore",
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
    """Hashes of the original binary"""

    sha256: str = Field(
        description="SHA256 hash of the original binary",
    )


class ProjectFileTarget(BaseModel):
    """Target schema for project.yml"""

    filename: str = Field(
        description="Name of the executable file",
    )
    source_root: Path = Field(
        validation_alias=AliasChoices("source-root", "source_root"),
        description="Base of the source code",
    )
    hash: Hash
    ghidra: GhidraConfig = Field(default_factory=GhidraConfig.default)


class ProjectFile(BaseModel):
    """File schema for project.yml"""

    targets: dict[str, ProjectFileTarget] = Field(
        description="List of targets",
    )


class UserFileTarget(BaseModel):
    """Target schema for user.yml"""

    path: Path = Field(
        description="Path to the original executable file",
    )


class UserFile(BaseModel):
    """File schema for user.yml"""

    targets: dict[str, UserFileTarget] = Field(
        description="List of targets",
    )


class BuildFileTarget(BaseModel):
    """Target schema for build.yml"""

    path: Path = Field(
        description="Path to the recompiled executable file, relative to the project path",
    )
    pdb: Path = Field(
        description="Path to the PDB file, relative to the project path",
    )


class BuildFile(BaseModel):
    """File schema for build.yml"""

    project: Path = Field(
        description="Path of the project directory"
    )
    targets: dict[str, BuildFileTarget] = Field(
        description="List of targets",
    )
