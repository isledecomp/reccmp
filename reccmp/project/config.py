"""Types for the configuration of a reccmp project"""

from pathlib import Path
from dataclasses import dataclass

from pydantic import AliasChoices, BaseModel, Field
import ruamel.yaml


_yaml = ruamel.yaml.YAML()


class YmlFileModel(BaseModel):
    @classmethod
    def from_file(cls, filename: Path):
        with filename.open("r") as f:
            return cls.model_validate(_yaml.load(f))

    @classmethod
    def from_str(cls, yaml: str):
        return cls.model_validate(_yaml.load(yaml))

    def write_file(self, filename: Path):
        with filename.open("w") as f:
            _yaml.dump(data=self.model_dump(mode="json"), stream=f)


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


class YmlReportConfig(BaseModel):
    ignore_functions: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-functions", "ignore_functions"),
    )

    @classmethod
    def default(cls) -> "YmlReportConfig":
        return cls(ignore_functions=[])


@dataclass
class Hash:
    sha256: str


class ProjectFileTarget(BaseModel):
    """Target schema for reccmp-project.yml"""

    filename: str
    source_root: Path = Field(
        validation_alias=AliasChoices("source-root", "source_root")
    )
    hash: Hash
    ghidra: YmlGhidraConfig = Field(default_factory=YmlGhidraConfig.default)
    report: YmlReportConfig = Field(default_factory=YmlReportConfig.default)


class ProjectFile(YmlFileModel):
    """File schema for reccmp-project.yml"""

    targets: dict[str, ProjectFileTarget]


@dataclass
class UserFileTarget:
    """Target schema for reccmp-user.yml"""

    path: Path


class UserFile(YmlFileModel):
    """File schema for reccmp-user.yml"""

    targets: dict[str, UserFileTarget]


@dataclass
class BuildFileTarget:
    """Target schema for reccmp-build.yml"""

    path: Path
    pdb: Path


class BuildFile(YmlFileModel):
    """File schema for reccmp-build.yml"""

    project: Path
    targets: dict[str, BuildFileTarget]
