"""Types for the configuration of a reccmp project"""

from pathlib import Path
from dataclasses import dataclass
from io import StringIO, TextIOBase
from pydantic import AliasChoices, BaseModel, Field
import ruamel.yaml
from .yml_extensions import PathSequence

_yaml = ruamel.yaml.YAML()


class YmlFileModel(BaseModel):
    @classmethod
    def from_file(cls, filename: Path):
        with filename.open("r") as f:
            return cls.model_validate(_yaml.load(f))

    @classmethod
    def from_str(cls, yaml: str):
        return cls.model_validate(_yaml.load(yaml))

    def _write_buf(self, buf: TextIOBase):
        data = self.model_dump(mode="json", exclude_defaults=True)
        _yaml.dump(data=data, stream=buf)

    def write_file(self, filename: Path):
        with filename.open("w") as f:
            self._write_buf(f)

    def to_str(self) -> str:
        with StringIO() as buf:
            self._write_buf(buf)
            return buf.getvalue()


class YmlGhidraConfig(BaseModel):
    ignore_types: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-types", "ignore_types"),
    )
    ignore_functions: list[int] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-functions", "ignore_functions"),
    )
    name_substitutions: list[tuple[str, str]] = Field(
        default_factory=list,
        validation_alias=AliasChoices("name-substitutions", "name_substitutions"),
    )
    allow_hash_mismatch: bool = Field(
        default=False,
        validation_alias=AliasChoices("allow-hash-mismatch", "allow_hash_mismatch"),
    )

    @classmethod
    def default(cls) -> "YmlGhidraConfig":
        return cls(
            ignore_types=[],
            ignore_functions=[],
            name_substitutions=[],
            allow_hash_mismatch=False,
        )


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
    source_root: PathSequence = Field(
        validation_alias=AliasChoices("source-root", "source_root"),
        default_factory=tuple,
    )
    hash: Hash
    data_sources: list[Path] = Field(
        validation_alias=AliasChoices("data-sources", "data_sources"),
        default_factory=list,
    )
    encoding: str | None = Field(default=None)
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
