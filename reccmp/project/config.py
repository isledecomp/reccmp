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
    target_id: str
    filename: str
    source_root: Path
    ghidra_config: GhidraConfig


@dataclass
class RecCmpBuiltTarget(RecCmpTarget):
    original_path: Path
    recompiled_path: Path
    recompiled_pdb: Path


class Hash(BaseModel):
    sha256: str


class ProjectFileTarget(BaseModel):
    filename: str
    source_root: Path = Field(
        validation_alias=AliasChoices("source-root", "source_root")
    )
    hash: Hash
    ghidra: GhidraConfig = Field(default_factory=GhidraConfig.default)


class ProjectFile(BaseModel):
    targets: dict[str, ProjectFileTarget]


class UserFileTarget(BaseModel):
    path: Path


class UserFile(BaseModel):
    targets: dict[str, UserFileTarget]


class BuildFileTarget(BaseModel):
    path: Path
    pdb: Path


class BuildFile(BaseModel):
    project: Path
    targets: dict[str, BuildFileTarget]
