"""Join reccmp markers to semantic declarations from the Clang AST.

The marker parser owns annotation syntax and addresses. Clang owns C++ names,
function and variable kinds, types, linkage, class membership, inheritance,
and virtual declarations. This module joins those two models by source location
and writes disposable JSON projections for downstream tools.

Compiler records arrive as per-TU observations. Link-namespace partitioning,
winner selection, and conflict derivation happen after collection — never by
globally collapsing bare ``semantic_id`` values first.
"""

from __future__ import annotations

# The optional execution backend imports this record model when first used.
# pylint: disable=cyclic-import

import json
import shlex
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence, TextIO

from reccmp.formats import TextFile
from reccmp.parser.codebase import DecompCodebase
from reccmp.parser.marker import MarkerType, ProjectAliases
from .variables import SourceConflict, SourceConflictVariant, SourceVariable

_VARIABLE_RANK = {"declaration": 0, "tentative": 1, "definition": 2}
_SCHEMA = "reccmp-source-index-v3"


class SourceIndexError(ValueError):
    """The source markers and compiler model cannot be joined unambiguously."""


@dataclass(frozen=True)
# pylint: disable=too-many-instance-attributes
class SourceDeclaration:
    """One semantic function declaration emitted by Clang."""

    semantic_id: str
    qualified_name: str
    semantic_kind: str
    calling_convention: str
    return_type: str
    parameter_types: tuple[str, ...]
    owning_class: str | None
    has_this: bool
    is_virtual: bool
    source_file: str
    line: int
    end_line: int
    is_definition: bool
    source_signature: str | None = None
    parameter_references: tuple[bool, ...] = ()
    parameter_reference_forms: tuple[str, ...] = ()
    linkage: str = ""
    storage_class: str = ""
    is_variadic: bool = False
    unit_id: str = ""
    target: str | None = None

    @property
    def prototype(self) -> str:
        """Render compiler-owned types for display, not ABI synchronization."""
        parameters = ", ".join(self.parameter_types) or "void"
        if self.is_variadic:
            parameters = f"{parameters}, ..." if self.parameter_types else "..."
        prefix = f"{self.return_type} " if self.return_type else ""
        return f"{prefix}{self.qualified_name}({parameters})"

    @property
    def is_external(self) -> bool:
        """Genuinely cross-TU linkage."""
        return self.linkage == "external"

    @property
    def signature(self) -> tuple[str, ...]:
        """The type identity a cross-TU consistency gate compares."""
        return (
            self.semantic_kind,
            self.calling_convention,
            self.return_type,
            *self.parameter_types,
            self.linkage,
            "..." if self.is_variadic else "",
        )

    @property
    def merge_key(self) -> tuple[str, ...]:
        """Identity used when grouping observations inside one link namespace."""
        if self.is_external:
            return (self.semantic_id,)
        return (self.unit_id, self.semantic_id)


@dataclass(frozen=True)
class SourceField:
    """One direct non-static source field emitted by Clang."""

    name: str
    type: str
    source_file: str
    line: int
    pointer_depth: int | None = None


@dataclass(frozen=True)
class SourceBaseVtable:
    """One vtable installed for a polymorphic base subobject."""

    address: int
    base_class: str


@dataclass(frozen=True)
# pylint: disable=too-many-instance-attributes
class SourceClass:
    """One complete C++ record definition emitted by Clang."""

    semantic_id: str
    qualified_name: str
    bases: tuple[str, ...]
    fields: tuple[SourceField, ...]
    virtual_declarations: tuple[str, ...]
    source_file: str
    line: int
    end_line: int
    asserted_size: int | None = None
    vtable_address: int | None = None
    base_vtables: tuple[SourceBaseVtable, ...] = ()
    unit_id: str = ""
    target: str | None = None


@dataclass(frozen=True)
class SourceMarker:
    """A reccmp marker and its compiler-owned declaration, when applicable."""

    address: int
    marker_kind: str
    source_file: str
    line: int
    declaration: SourceDeclaration | None
    marker_name: str | None = None
    folded: bool = False
    target: str | None = None

    @property
    def name(self) -> str:
        """Compiler identity, or the name attached to a non-body marker."""
        return (
            self.declaration.qualified_name
            if self.declaration
            else self.marker_name or ""
        )


@dataclass(frozen=True)
class _SizeAssertion:
    unit_id: str
    qualified_name: str
    asserted_size: int


@dataclass(frozen=True)
class _NamespaceRecords:
    """Winners and conflicts derived inside one link namespace."""

    declarations: tuple[SourceDeclaration, ...]
    variables: tuple[SourceVariable, ...]
    classes: tuple[SourceClass, ...]
    conflicts: tuple[SourceConflict, ...]
    size_assertions: dict[str, int]


@dataclass
class TranslationUnitRecords:
    """Raw compiler observations from one translation unit.

    No winner selection or conflict tracking happens here — that is derived
    after observations are grouped by link namespace.
    """

    unit_id: str
    declarations: list[SourceDeclaration] = field(default_factory=list)
    variables: list[SourceVariable] = field(default_factory=list)
    classes: list[SourceClass] = field(default_factory=list)
    size_assertions: list[_SizeAssertion] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)

    def add(self, record: Mapping[str, Any]) -> None:
        """Store one compiler observation from this unit."""
        values = dict(record)
        kind = values.pop("record")
        if kind == "dependency":
            self.dependencies = [str(path) for path in values.get("files") or ()]
            return
        if kind == "declaration":
            self.declarations.append(
                _declaration_from_dict({**values, "unit_id": self.unit_id})
            )
        elif kind == "variable":
            variable = _variable_from_dict({**values, "unit_id": self.unit_id})
            if variable.is_external:
                self.variables.append(variable)
        elif kind == "class":
            self.classes.append(_class_from_dict({**values, "unit_id": self.unit_id}))
        elif kind == "size-assertion":
            self.size_assertions.append(
                _SizeAssertion(
                    unit_id=self.unit_id,
                    qualified_name=str(values["qualified_name"]),
                    asserted_size=int(values["asserted_size"]),
                )
            )
        else:
            raise SourceIndexError(
                f"the source indexer emitted an unknown record: {kind!r}"
            )

    @classmethod
    def load(cls, path: Path, unit_id: str) -> "TranslationUnitRecords":
        """Stream one NDJSON artifact into a TU record set."""
        unit = cls(unit_id=unit_id)
        with path.open(encoding="utf-8") as handle:
            unit.extend_stream(handle)
        return unit

    def extend_stream(self, handle: TextIO) -> None:
        for line in handle:
            if line.strip():
                self.add(json.loads(line))


def relative_unit_id(
    repository: Path, main_file: str | Path, compilation_root: Path | None = None
) -> str:
    """Repo-relative identity of a translation unit's main file."""
    path = Path(main_file)
    if compilation_root is not None:
        try:
            path = repository / path.relative_to(compilation_root)
        except ValueError:
            pass
    try:
        return path.resolve().relative_to(repository.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def derive_namespace(
    units: Sequence[TranslationUnitRecords],
    *,
    target: str | None = None,
    unit_ids: set[str] | None = None,
) -> _NamespaceRecords:
    """Partition TU observations, then derive winners and conflicts."""

    def belongs(unit_id: str) -> bool:
        return unit_ids is None or unit_id in unit_ids

    selected = [unit for unit in units if belongs(unit.unit_id)]
    declarations = [item for unit in selected for item in unit.declarations]
    variables = [item for unit in selected for item in unit.variables]
    classes = [item for unit in selected for item in unit.classes]
    assertions = [item for unit in selected for item in unit.size_assertions]

    derived_declarations, declaration_conflicts = _derive_entities(
        declarations,
        key=lambda item: item.merge_key,
        rank=lambda item: 1 if item.is_definition else 0,
        record_kind="declaration",
        target=target,
    )
    derived_variables, variable_conflicts = _derive_entities(
        variables,
        key=lambda item: (item.semantic_id,),
        rank=lambda item: _VARIABLE_RANK.get(item.definition_kind, 0),
        record_kind="variable",
        target=target,
    )
    derived_classes = _derive_classes(classes, target=target)
    size_assertions = _derive_size_assertions(assertions)
    return _NamespaceRecords(
        declarations=derived_declarations,
        variables=derived_variables,
        classes=tuple(
            replace(item, asserted_size=size_assertions.get(item.qualified_name))
            for item in derived_classes
        ),
        conflicts=declaration_conflicts + variable_conflicts,
        size_assertions=size_assertions,
    )


# Test/fixture helper: accumulate observations across units without merging.
class SourceCollector:
    """Fixture helper that gathers ``TranslationUnitRecords`` by unit id."""

    def __init__(self, repository: Path, compilation_root: Path | None = None) -> None:
        self.repository = repository.resolve()
        self.compilation_root = compilation_root
        self.units: dict[str, TranslationUnitRecords] = {}

    def unit_id_for(self, main_file: str | Path) -> str:
        return relative_unit_id(self.repository, main_file, self.compilation_root)

    def collect_record(self, record: Mapping[str, Any], *, unit_id: str = "") -> None:
        self.units.setdefault(unit_id, TranslationUnitRecords(unit_id)).add(record)

    def collect_records(self, records: str, *, unit_id: str = "") -> None:
        for line in records.splitlines():
            if line.strip():
                self.collect_record(json.loads(line), unit_id=unit_id)

    @property
    def variables(self) -> list[SourceVariable]:
        return [item for unit in self.units.values() for item in unit.variables]

    def derive(
        self, *, target: str | None = None, unit_ids: set[str] | None = None
    ) -> _NamespaceRecords:
        return derive_namespace(
            tuple(self.units.values()), target=target, unit_ids=unit_ids
        )


def _derive_entities(
    observations: Sequence[Any],
    *,
    key,
    rank,
    record_kind: str,
    target: str | None,
) -> tuple[tuple[Any, ...], tuple[SourceConflict, ...]]:
    groups: dict[tuple[str, ...], list[Any]] = {}
    for item in observations:
        groups.setdefault(key(item), []).append(item)

    winners: list[Any] = []
    conflicts: list[SourceConflict] = []
    for group in groups.values():
        winner = group[0]
        for item in group[1:]:
            if rank(item) > rank(winner):
                winner = item
        winners.append(replace(winner, target=target) if target is not None else winner)

        variants: dict[tuple[str, ...], list[str]] = {}
        for item in group:
            location = f"{item.source_file}:{item.line}"
            variants.setdefault(item.signature, [])
            if location not in variants[item.signature]:
                variants[item.signature].append(location)
        if len(variants) > 1:
            sample = group[0]
            conflicts.append(
                SourceConflict(
                    semantic_id=sample.semantic_id,
                    qualified_name=sample.qualified_name,
                    record_kind=record_kind,
                    variants=tuple(
                        SourceConflictVariant(
                            signature=signature, locations=tuple(locations)
                        )
                        for signature, locations in variants.items()
                    ),
                    target=target,
                )
            )
    return tuple(winners), tuple(conflicts)


def _derive_classes(
    observations: Sequence[SourceClass], *, target: str | None
) -> tuple[SourceClass, ...]:
    best: dict[str, SourceClass] = {}
    for item in observations:
        previous = best.get(item.semantic_id)
        if previous is None or (not previous.line and item.line):
            best[item.semantic_id] = (
                replace(item, target=target) if target is not None else item
            )
    return tuple(best.values())


def _derive_size_assertions(assertions: Sequence[_SizeAssertion]) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for item in assertions:
        previous = sizes.get(item.qualified_name)
        if previous is not None and previous != item.asserted_size:
            raise SourceIndexError(
                f"{item.qualified_name} has conflicting size assertions: "
                f"{previous:#x} and {item.asserted_size:#x}"
            )
        sizes[item.qualified_name] = item.asserted_size
    return sizes


def _command_arguments(entry: dict[str, Any]) -> list[str]:
    arguments = entry.get("arguments")
    if arguments:
        return [str(item) for item in arguments]
    return shlex.split(str(entry["command"]), posix=True)


def record_command(
    entry: dict[str, Any], indexer: str, clang: str | None = None
) -> list[str]:
    """Normalize a compile-database entry into an indexer driver command."""
    arguments = _command_arguments(entry)
    compiler = clang or arguments[0]
    filtered: list[str] = []
    skip_next = False
    for argument in arguments[1:]:
        if skip_next:
            skip_next = False
            continue
        if argument in {"-c", "/c", "-o", "-MF", "-MT", "-MQ"}:
            skip_next = argument in {"-o", "-MF", "-MT", "-MQ"}
            continue
        # codespell:ignore-begin
        if argument.startswith(("/Fo", "/Fd", "-o")):
            # codespell:ignore-end
            continue
        filtered.append(argument)
    try:
        separator = filtered.index("--")
    except ValueError:
        separator = len(filtered)
    return [
        indexer,
        compiler,
        *filtered[:separator],
        "-fsyntax-only",
        *filtered[separator:],
    ]


def _declaration_from_dict(values: Mapping[str, Any]) -> SourceDeclaration:
    data = dict(values)
    for key in ("parameter_types", "parameter_references", "parameter_reference_forms"):
        data[key] = tuple(data.get(key) or ())
    data.pop("declaration_key", None)
    return SourceDeclaration(**data)


def _variable_from_dict(values: Mapping[str, Any]) -> SourceVariable:
    return SourceVariable(**dict(values))


def _conflict_from_dict(values: Mapping[str, Any]) -> SourceConflict:
    return SourceConflict(
        semantic_id=str(values["semantic_id"]),
        qualified_name=str(values["qualified_name"]),
        record_kind=str(values["record_kind"]),
        target=values.get("target"),
        variants=tuple(
            SourceConflictVariant(
                signature=tuple(variant.get("signature") or ()),
                locations=tuple(variant.get("locations") or ()),
            )
            for variant in values.get("variants") or ()
        ),
    )


def _class_from_dict(values: Mapping[str, Any]) -> SourceClass:
    return SourceClass(
        **{
            **values,
            "bases": tuple(values["bases"]),
            "fields": tuple(SourceField(**field) for field in values["fields"]),
            "virtual_declarations": tuple(values["virtual_declarations"]),
            "base_vtables": tuple(
                SourceBaseVtable(**item) for item in values.get("base_vtables", ())
            ),
        }
    )


def _marker_projection(marker: SourceMarker) -> dict[str, Any]:
    """Serialize a marker with a declaration key instead of a nested copy."""
    payload = {
        "address": marker.address,
        "marker_kind": marker.marker_kind,
        "source_file": marker.source_file,
        "line": marker.line,
        "marker_name": marker.marker_name,
        "folded": marker.folded,
        "target": marker.target,
        "declaration_key": None,
    }
    if marker.declaration is not None:
        payload["declaration_key"] = [
            marker.declaration.target,
            marker.declaration.semantic_id,
        ]
    return payload


def _join_markers(
    repository: Path,
    target: str,
    source_paths: Sequence[Path],
    namespace: _NamespaceRecords,
    *,
    aliases: ProjectAliases | None,
) -> tuple[list[SourceClass], list[SourceMarker]]:
    files = tuple(TextFile.from_files(source_paths))
    codebase = DecompCodebase(files, target, aliases=aliases)
    declarations = namespace.declarations
    by_location: dict[tuple[str, int], list[SourceDeclaration]] = {}
    for declaration in declarations:
        if declaration.is_definition:
            by_location.setdefault(
                (declaration.source_file, declaration.line), []
            ).append(declaration)

    markers: list[SourceMarker] = []
    for method_symbol in (
        *codebase.iter_line_functions(),
        *codebase.iter_name_functions(),
    ):
        relative = (
            Path(method_symbol.filename)
            .resolve()
            .relative_to(repository.resolve())
            .as_posix()
        )
        candidates = by_location.get((relative, method_symbol.line_number), [])
        marker_declaration: SourceDeclaration | None = None
        # Name-reference markers (TEMPLATE/SYNTHETIC/LIBRARY, and FUNCTION with a
        # name comment e.g. `FUNCTION: X 0x... SYMBOL` + `// ??0foo@@QAE@XZ`)
        # point at their name line, not a definition, so they cannot bind by
        # location.
        if (
            method_symbol.type
            in {
                MarkerType.FUNCTION,
                MarkerType.STUB,
            }
            and not method_symbol.is_nameref()
        ):
            if len(candidates) != 1:
                raise SourceIndexError(
                    f"{relative}:{method_symbol.line_number}: {method_symbol.type.name} "
                    f"0x{method_symbol.offset:08x} "
                    f"binds to {len(candidates)} function definitions"
                )
            marker_declaration = candidates[0]
        markers.append(
            SourceMarker(
                address=method_symbol.offset,
                marker_kind=method_symbol.type.name,
                source_file=relative,
                line=method_symbol.line_number,
                declaration=marker_declaration,
                folded=method_symbol.is_folded,
                target=target,
                marker_name=(
                    method_symbol.name if marker_declaration is None else None
                ),
            )
        )

    classes = list(namespace.classes)
    class_by_location = {
        (item.source_file, item.line): index for index, item in enumerate(classes)
    }
    class_by_name = {item.qualified_name: index for index, item in enumerate(classes)}
    for vtable_symbol in codebase.iter_vtables():
        relative = (
            Path(vtable_symbol.filename)
            .resolve()
            .relative_to(repository.resolve())
            .as_posix()
        )
        key = (relative, vtable_symbol.line_number)
        index = class_by_location.get(key)
        if index is None:
            index = class_by_name.get(vtable_symbol.name)
        if index is None:
            source_class = SourceClass(
                semantic_id=f"record:{vtable_symbol.name}",
                qualified_name=vtable_symbol.name,
                bases=(),
                fields=(),
                virtual_declarations=(),
                source_file=relative,
                line=vtable_symbol.line_number,
                end_line=vtable_symbol.line_number,
                vtable_address=vtable_symbol.offset,
                target=target,
            )
            classes.append(source_class)
            class_by_name[source_class.qualified_name] = len(classes) - 1
            continue
        source_class = classes[index]
        base_class = vtable_symbol.base_class
        class_names = {
            source_class.qualified_name,
            source_class.qualified_name.rsplit("::", 1)[-1],
        }
        if base_class is not None and base_class not in class_names:
            base_vtable = SourceBaseVtable(vtable_symbol.offset, base_class)
            if base_vtable in source_class.base_vtables:
                raise SourceIndexError(
                    f"{relative}:{vtable_symbol.line_number}: duplicate VTABLE marker "
                    f"for base {base_class}"
                )
            classes[index] = replace(
                source_class,
                base_vtables=(*source_class.base_vtables, base_vtable),
            )
            continue
        if source_class.vtable_address is not None:
            raise SourceIndexError(
                f"{relative}:{vtable_symbol.line_number}: class has more than one "
                "primary VTABLE marker"
            )
        classes[index] = replace(source_class, vtable_address=vtable_symbol.offset)
    return classes, markers


class SourceIndex:
    """Canonical marker plus Clang semantic source index."""

    def __init__(
        self,
        *,
        declarations: Iterable[SourceDeclaration],
        classes: Iterable[SourceClass],
        markers: Iterable[SourceMarker],
        variables: Iterable[SourceVariable] = (),
        conflicts: Iterable[SourceConflict] = (),
    ) -> None:
        self.declarations = tuple(
            sorted(declarations, key=lambda item: item.semantic_id)
        )
        self.classes = tuple(sorted(classes, key=lambda item: item.semantic_id))
        self.markers = tuple(
            sorted(markers, key=lambda item: (item.address, item.source_file))
        )
        self.variables = tuple(sorted(variables, key=lambda item: item.semantic_id))
        self.conflicts = tuple(sorted(conflicts, key=lambda item: item.semantic_id))

    @classmethod
    def from_units(
        cls,
        repository: Path,
        target: str,
        source_paths: Sequence[Path],
        units: Sequence[TranslationUnitRecords],
        *,
        unit_ids: set[str] | None = None,
        aliases: ProjectAliases | None = None,
    ) -> "SourceIndex":
        """Derive one link namespace from TU observations, then join markers."""
        namespace = derive_namespace(units, target=target, unit_ids=unit_ids)
        classes, markers = _join_markers(
            repository, target, source_paths, namespace, aliases=aliases
        )
        return cls(
            declarations=namespace.declarations,
            classes=classes,
            markers=markers,
            variables=namespace.variables,
            conflicts=namespace.conflicts,
        )

    @classmethod
    def from_collector(
        cls,
        repository: Path,
        target: str,
        source_paths: Sequence[Path],
        collector: SourceCollector,
        *,
        unit_ids: set[str] | None = None,
        aliases: ProjectAliases | None = None,
    ) -> "SourceIndex":
        """Derive from a fixture ``SourceCollector`` (tests)."""
        return cls.from_units(
            repository,
            target,
            source_paths,
            tuple(collector.units.values()),
            unit_ids=unit_ids,
            aliases=aliases,
        )

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "SourceIndex":
        """Read the public JSON projection back into its canonical records."""
        schema = document.get("schema")
        if schema not in {_SCHEMA, "reccmp-source-index-v2"}:
            raise SourceIndexError("unsupported source-index schema")
        declarations = tuple(
            _declaration_from_dict(item) for item in document["declarations"]
        )
        by_key = {(item.target, item.semantic_id): item for item in declarations}
        markers: list[SourceMarker] = []
        for item in document["markers"]:
            values = dict(item)
            if "declaration_key" in values:
                key = values.pop("declaration_key")
                values.pop("declaration", None)
                declaration = by_key.get(tuple(key)) if key else None
            elif values.get("declaration"):
                declaration = _declaration_from_dict(values.pop("declaration"))
            else:
                values.pop("declaration", None)
                declaration = None
            markers.append(SourceMarker(**values, declaration=declaration))
        return cls(
            declarations=declarations,
            classes=(_class_from_dict(item) for item in document["classes"]),
            markers=markers,
            variables=(
                _variable_from_dict(item) for item in document.get("variables", ())
            ),
            conflicts=(
                _conflict_from_dict(item) for item in document.get("conflicts", ())
            ),
        )

    def functions_by_address(
        self, *, target: str | None = None
    ) -> dict[int, SourceMarker]:
        """Return one owner per address, preferring an unfolded body over aliases."""
        functions: dict[int, SourceMarker] = {}
        for marker in self.markers:
            if target is not None and marker.target != target:
                continue
            if not marker.name:
                raise SourceIndexError(
                    f"{marker.source_file}:{marker.line}: marker has no semantic identity"
                )
            previous = functions.get(marker.address)
            if previous is not None:
                if marker.folded and not previous.folded:
                    continue
                if marker.folded == previous.folded:
                    raise SourceIndexError(
                        f"0x{marker.address:08x} has more than one source owner"
                    )
            functions[marker.address] = marker
        return functions

    @classmethod
    def from_compile_database(
        cls,
        repository: Path,
        compilation_database: Path,
        targets: Mapping[str, Sequence[Path]],
        *,
        clang: str | None = None,
        jobs: int | None = None,
        cache_dir: Path | None = None,
        force: bool = False,
        aliases: ProjectAliases | None = None,
    ) -> "SourceIndex":
        """Collect direct AST records natively, once for all marker targets.

        Expects to run in the same filesystem as the compile database (typically
        inside the pinned analysis image). ``RECCMP_SOURCE_INDEXER`` or
        ``reccmp-source-indexer`` on ``PATH`` supplies a prebuilt collector;
        otherwise the collector is built once into ``cache_dir`` against LLVM 19.
        """
        # pylint: disable=import-outside-toplevel
        from .batch import collect_compile_database

        return collect_compile_database(
            repository,
            compilation_database,
            targets,
            clang=clang,
            jobs=jobs,
            cache_dir=cache_dir,
            force=force,
            aliases=aliases,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "markers": [_marker_projection(item) for item in self.markers],
            "declarations": [asdict(item) for item in self.declarations],
            "classes": [asdict(item) for item in self.classes],
            "variables": [asdict(item) for item in self.variables],
            "conflicts": [asdict(item) for item in self.conflicts],
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(self.to_dict(), separators=(",", ":")) + "\n"
        encoded = content.encode("utf-8")
        if not path.is_file() or path.read_bytes() != encoded:
            path.write_bytes(encoded)
