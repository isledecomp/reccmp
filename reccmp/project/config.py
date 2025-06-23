"""Types for the configuration of a reccmp project"""

from pathlib import Path
from dataclasses import dataclass

from pydantic import AliasChoices, BaseModel, Field


class YmlGhidraConfig(BaseModel):
    ignore_types: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-types", "ignore_types"),
    )
    ignore_functions: list[int] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-functions", "ignore_functions"),
    )

    @classmethod
    def default(cls) -> "YmlGhidraConfig":
        return cls(ignore_types=[], ignore_functions=[])


@dataclass
class Hash:
    sha256: str


class ProjectFileTarget(BaseModel):
    """Target schema for project.yml"""

    filename: str
    source_root: Path = Field(
        validation_alias=AliasChoices("source-root", "source_root")
    )
    hash: Hash
    ghidra: YmlGhidraConfig = Field(default_factory=YmlGhidraConfig.default)


class ProjectFile(BaseModel):
    """File schema for project.yml"""

    targets: dict[str, ProjectFileTarget]


@dataclass
class UserFileTarget:
    """Target schema for user.yml"""

    path: Path


class UserFile(BaseModel):
    """File schema for user.yml"""

    targets: dict[str, UserFileTarget]


@dataclass
class BuildFileTarget:
    """Target schema for build.yml"""

    path: Path
    pdb: Path


class BuildFile(BaseModel):
    """File schema for build.yml"""

    project: Path
    targets: dict[str, BuildFileTarget]
