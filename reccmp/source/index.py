"""Join reccmp markers to semantic declarations from the Clang AST.

The marker parser owns annotation syntax and addresses. Clang owns C++ names,
function kinds, types, class membership, inheritance, and virtual declarations.
This module only joins those two models by source location and writes disposable
JSON projections for downstream tools.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

from reccmp.formats import TextFile
from reccmp.parser.codebase import DecompCodebase
from reccmp.parser.marker import MarkerType, ProjectAliases

_FUNCTION_KINDS = {
    "FunctionDecl",
    "CXXMethodDecl",
    "CXXConstructorDecl",
    "CXXDestructorDecl",
    "CXXConversionDecl",
}
_RECORD_KINDS = {
    "CXXRecordDecl",
    "ClassTemplateSpecializationDecl",
}
_SCOPE_KINDS = _RECORD_KINDS | {"NamespaceDecl"}


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


@dataclass(frozen=True)
class SourceField:
    """One direct non-static source field emitted by Clang."""

    name: str
    type: str
    source_file: str
    line: int


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


@dataclass(frozen=True)
class SourceMarker:
    """A reccmp marker and its compiler-owned declaration, when applicable."""

    address: int
    marker_kind: str
    source_file: str
    line: int
    declaration: SourceDeclaration | None
    marker_name: str | None = None


@dataclass(frozen=True)
class _Location:
    file: str
    line: int
    end_line: int


def _location_part(value: dict[str, Any]) -> dict[str, Any]:
    for key in ("expansionLoc", "spellingLoc"):
        nested = value.get(key)
        if isinstance(nested, dict):
            return nested
    return value


def _location(node: dict[str, Any], fallback_file: str) -> _Location:
    location = _location_part(node.get("loc") or {})
    start = _location_part((node.get("range") or {}).get("begin") or {})
    end = _location_part((node.get("range") or {}).get("end") or {})
    source_file = str(start.get("file") or location.get("file") or fallback_file)
    line = int(start.get("line") or location.get("line") or 0)
    return _Location(source_file, line, int(end.get("line") or line))


def _explicit_file(node: dict[str, Any]) -> str:
    location = _location_part(node.get("loc") or {})
    start = _location_part((node.get("range") or {}).get("begin") or {})
    return str(start.get("file") or location.get("file") or "")


def _qualified(scope: str, name: str) -> str:
    return f"{scope}::{name}" if scope else name


def _scope_component(node: dict[str, Any]) -> str:
    name = str(node.get("name") or "")
    if node.get("kind") != "ClassTemplateSpecializationDecl":
        return name
    arguments = []
    for child in node.get("inner", ()):
        if child.get("kind") != "TemplateArgument":
            continue
        argument_type = _canonical_type(child)
        value = child.get("value")
        arguments.append(argument_type or str(value or ""))
    rendered = ", ".join(argument for argument in arguments if argument)
    return f"{name}<{rendered}>" if rendered else name


def _canonical_type(node: dict[str, Any]) -> str:
    type_info = node.get("type") or {}
    return str(type_info.get("desugaredQualType") or type_info.get("qualType") or "")


def _return_type(node: dict[str, Any]) -> str:
    if node.get("kind") in {"CXXConstructorDecl", "CXXDestructorDecl"}:
        return ""
    function_type = _canonical_type(node)
    return function_type.split("(", 1)[0].strip()


def _parameters(node: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        _canonical_type(child)
        for child in node.get("inner", ())
        if child.get("kind") == "ParmVarDecl"
    )


def _is_definition(node: dict[str, Any]) -> bool:
    if node.get("isThisDeclarationADefinition"):
        return True
    return any(
        child.get("kind") in {"CompoundStmt", "CXXTryStmt"}
        for child in node.get("inner", ())
    )


def _descendants(node: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield node
    for child in node.get("inner", ()):
        yield from _descendants(child)


def _size_assertion(node: dict[str, Any], scope: str) -> tuple[str, int] | None:
    if node.get("kind") != "StaticAssertDecl":
        return None
    expression = next(
        (
            child
            for child in node.get("inner", ())
            if child.get("kind") == "BinaryOperator"
        ),
        None,
    )
    if expression is None or expression.get("opcode") != "==":
        return None
    size_of = next(
        (
            child
            for child in _descendants(expression)
            if child.get("kind") == "UnaryExprOrTypeTraitExpr"
            and child.get("name") == "sizeof"
            and (child.get("argType") or {}).get("qualType")
        ),
        None,
    )
    literal = next(
        (
            child
            for child in _descendants(expression)
            if child.get("kind") == "IntegerLiteral" and child.get("value") is not None
        ),
        None,
    )
    if size_of is None or literal is None:
        return None
    class_name = str(size_of["argType"]["qualType"])
    if "::" not in class_name and scope:
        class_name = _qualified(scope, class_name)
    return class_name, int(str(literal["value"]), 0)


def _semantic_kind(node: dict[str, Any], owning_class: str | None, scope: str) -> str:
    kind = node.get("kind")
    if kind == "CXXConstructorDecl":
        return "constructor"
    if kind == "CXXDestructorDecl":
        return "destructor"
    if owning_class is not None:
        return (
            "static_method"
            if node.get("storageClass") == "static"
            else "instance_method"
        )
    return "namespace_function" if scope else "free_function"


def _calling_convention(node: dict[str, Any], semantic_kind: str) -> str:
    explicit = str(node.get("callingConvention") or node.get("callingConv") or "")
    function_type = _canonical_type(node)
    combined = f"{explicit} {function_type}".lower()
    for spelling in ("thiscall", "stdcall", "fastcall", "vectorcall", "cdecl"):
        if spelling in combined:
            return f"__{spelling}"
    # On the x86 MS ABI this is a compiler consequence of the semantic kind,
    # not an inference from punctuation in a source spelling.
    return (
        "__thiscall"
        if semantic_kind in {"constructor", "destructor", "instance_method"}
        else "__cdecl"
    )


def _semantic_id(node: dict[str, Any], qualified_name: str) -> str:
    mangled = node.get("mangledName")
    if mangled:
        return str(mangled)
    signature = ",".join(_parameters(node))
    return f"{node.get('kind')}:{qualified_name}({signature})"


def _is_virtual(node: dict[str, Any]) -> bool:
    """Clang marks introducing virtuals directly and overrides with an attribute."""

    return bool(node.get("virtual")) or any(
        child.get("kind") in {"OverrideAttr", "FinalAttr"}
        for child in node.get("inner", ())
    )


class _AstCollector:
    def __init__(self, repository: Path, compilation_root: Path | None = None) -> None:
        self.repository = repository.resolve()
        self.compilation_root = compilation_root
        self.contexts: dict[str, tuple[str, bool]] = {}
        self.declarations: dict[str, SourceDeclaration] = {}
        self.classes: dict[str, SourceClass] = {}
        self.size_assertions: dict[str, int] = {}
        self.current_file = ""

    def collect(self, document: dict[str, Any], main_file: Path) -> None:
        self._collect_contexts(document, "")
        self.current_file = str(main_file.resolve())
        self._walk(document, "", str(main_file.resolve()))

    def _collect_contexts(self, node: dict[str, Any], scope: str) -> None:
        kind = node.get("kind")
        name = _scope_component(node)
        child_scope = scope
        if kind in _SCOPE_KINDS and name:
            child_scope = _qualified(scope, name)
            node_id = node.get("id")
            if node_id:
                self.contexts[str(node_id)] = (child_scope, kind in _RECORD_KINDS)
        for child in node.get("inner", ()):
            self._collect_contexts(child, child_scope)

    def _relative(self, source_file: str) -> str:
        path = Path(source_file)
        if self.compilation_root is not None:
            try:
                suffix = path.relative_to(self.compilation_root)
            except ValueError:
                pass
            else:
                path = self.repository / suffix
        try:
            return path.resolve().relative_to(self.repository).as_posix()
        except ValueError:
            return path.as_posix()

    def _walk(self, node: dict[str, Any], scope: str, fallback_file: str) -> None:
        kind = node.get("kind")
        name = str(node.get("name") or "")
        scope_name = _scope_component(node)
        explicit_file = _explicit_file(node)
        if explicit_file:
            self.current_file = explicit_file
        location = _location(node, self.current_file or fallback_file)
        child_scope = scope
        if kind in _SCOPE_KINDS and scope_name:
            child_scope = _qualified(scope, scope_name)

        if kind in _RECORD_KINDS and name and node.get("completeDefinition"):
            qualified_name = child_scope
            bases = tuple(
                str(
                    (base.get("type") or {}).get("desugaredQualType")
                    or (base.get("type") or {}).get("qualType")
                    or ""
                )
                for base in node.get("bases", ())
            )
            virtuals = tuple(
                _semantic_id(
                    child, _qualified(qualified_name, str(child.get("name") or ""))
                )
                for child in node.get("inner", ())
                if child.get("kind") in _FUNCTION_KINDS and _is_virtual(child)
            )
            fields = tuple(
                SourceField(
                    name=str(child.get("name")),
                    type=str(
                        (child.get("type") or {}).get("desugaredQualType")
                        or (child.get("type") or {}).get("qualType")
                        or ""
                    ),
                    source_file=self._relative(_location(child, location.file).file),
                    line=_location(child, location.file).line,
                )
                for child in node.get("inner", ())
                if child.get("kind") == "FieldDecl" and child.get("name")
            )
            source_class = SourceClass(
                semantic_id=f"record:{qualified_name}",
                qualified_name=qualified_name,
                bases=bases,
                fields=fields,
                virtual_declarations=virtuals,
                source_file=self._relative(location.file),
                line=location.line,
                end_line=location.end_line,
            )
            class_previous = self.classes.get(source_class.semantic_id)
            if class_previous is None or (
                not class_previous.line and source_class.line
            ):
                self.classes[source_class.semantic_id] = source_class

        if kind in _FUNCTION_KINDS and name and not node.get("isImplicit"):
            context = self.contexts.get(str(node.get("parentDeclContextId") or ""))
            semantic_scope = context[0] if context else scope
            owning_class = semantic_scope if context and context[1] else None
            if owning_class is None and kind != "FunctionDecl":
                owning_class = scope or None
            qualified_name = _qualified(semantic_scope, name)
            semantic_kind = _semantic_kind(
                node, owning_class, semantic_scope if owning_class is None else ""
            )
            declaration = SourceDeclaration(
                semantic_id=_semantic_id(node, qualified_name),
                qualified_name=qualified_name,
                semantic_kind=semantic_kind,
                calling_convention=_calling_convention(node, semantic_kind),
                return_type=_return_type(node),
                parameter_types=_parameters(node),
                owning_class=owning_class,
                has_this=semantic_kind
                in {"constructor", "destructor", "instance_method"},
                is_virtual=_is_virtual(node),
                source_file=self._relative(location.file),
                line=location.line,
                end_line=location.end_line,
                is_definition=_is_definition(node),
            )
            declaration_previous = self.declarations.get(declaration.semantic_id)
            if declaration_previous is None or (
                declaration.is_definition and not declaration_previous.is_definition
            ):
                self.declarations[declaration.semantic_id] = declaration

        assertion = _size_assertion(node, scope)
        if assertion is not None:
            class_name, asserted_size = assertion
            previous_size = self.size_assertions.get(class_name)
            if previous_size is not None and previous_size != asserted_size:
                raise SourceIndexError(
                    f"{class_name} has conflicting size assertions: "
                    f"{previous_size:#x} and {asserted_size:#x}"
                )
            self.size_assertions[class_name] = asserted_size

        for child in node.get("inner", ()):
            self._walk(child, child_scope, fallback_file)


def _command_arguments(entry: dict[str, Any]) -> list[str]:
    arguments = entry.get("arguments")
    if arguments:
        return [str(item) for item in arguments]
    return shlex.split(str(entry["command"]), posix=True)


def _ast_command(
    entry: dict[str, Any], clang: str | None, command_prefix: Sequence[str]
) -> list[str]:
    arguments = _command_arguments(entry)
    compiler = [clang or arguments[0]] if not command_prefix else list(command_prefix)
    filtered: list[str] = []
    skip_next = False
    for argument in arguments[1:]:
        if skip_next:
            skip_next = False
            continue
        if argument in {"-c", "/c", "-o", "-MF", "-MT", "-MQ"}:
            skip_next = argument in {"-o", "-MF", "-MT", "-MQ"}
            continue
        if argument.startswith(("/Fo", "/Fd", "-o")):
            continue
        filtered.append(argument)
    try:
        separator = filtered.index("--")
    except ValueError:
        separator = len(filtered)
    ast_options = ["-fsyntax-only", "-Xclang", "-ast-dump=json"]
    return [*compiler, *filtered[:separator], *ast_options, *filtered[separator:]]


def _emit_ast(
    entry: dict[str, Any],
    clang: str | None,
    command_prefix: Sequence[str],
    execution_cwd: Path | None,
) -> dict[str, Any]:
    result = subprocess.run(
        _ast_command(entry, clang, command_prefix),
        cwd=execution_cwd or entry.get("directory"),
        check=False,
        capture_output=True,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        stderr = result.stderr.decode(errors="replace")
        raise SourceIndexError(
            f"Clang did not emit an AST for {entry.get('file')}: {stderr}"
        ) from error


class SourceIndex:
    """Canonical marker plus Clang semantic source index."""

    def __init__(
        self,
        *,
        declarations: Iterable[SourceDeclaration],
        classes: Iterable[SourceClass],
        markers: Iterable[SourceMarker],
    ) -> None:
        self.declarations = tuple(
            sorted(declarations, key=lambda item: item.semantic_id)
        )
        self.classes = tuple(sorted(classes, key=lambda item: item.semantic_id))
        self.markers = tuple(
            sorted(markers, key=lambda item: (item.address, item.source_file))
        )

    @classmethod
    # The optional execution arguments allow compilation databases produced in
    # containers to be replayed without teaching reccmp about one container runtime.
    # pylint: disable=too-many-arguments
    def from_compilation_database(
        cls,
        repository: Path,
        compilation_database: Path,
        target: str,
        *,
        marker_paths: Sequence[Path] | None = None,
        translation_units: Sequence[Path] | None = None,
        aliases: ProjectAliases | None = None,
        clang: str | None = None,
        command_prefix: Sequence[str] = (),
        compilation_root: Path | None = None,
        execution_cwd: Path | None = None,
    ) -> "SourceIndex":
        database = json.loads(compilation_database.read_text(encoding="utf-8"))
        wanted_units = (
            {path.resolve() for path in translation_units}
            if translation_units is not None
            else None
        )
        entries = [
            entry
            for entry in database
            if wanted_units is None
            or (Path(entry.get("directory") or ".") / entry["file"]).resolve()
            in wanted_units
        ]
        collector = _AstCollector(repository, compilation_root)
        for entry in entries:
            collector.collect(
                _emit_ast(entry, clang, command_prefix, execution_cwd),
                Path(entry.get("directory") or ".") / entry["file"],
            )
        parsed_marker_paths = marker_paths or tuple(
            (Path(entry.get("directory") or ".") / entry["file"]).resolve()
            for entry in entries
        )
        return cls._from_collector(
            repository, target, parsed_marker_paths, collector, aliases=aliases
        )

    @classmethod
    # This is the multi-image form of from_compilation_database. The compiler
    # AST is expensive, so collect it once and bind each marker target against
    # its own physical source roots before combining the disposable index.
    # pylint: disable=too-many-arguments
    def from_compilation_database_targets(
        cls,
        repository: Path,
        compilation_database: Path,
        targets: Mapping[str, Sequence[Path]],
        *,
        aliases: ProjectAliases | None = None,
        clang: str | None = None,
        command_prefix: Sequence[str] = (),
        compilation_root: Path | None = None,
        execution_cwd: Path | None = None,
    ) -> "SourceIndex":
        database = json.loads(compilation_database.read_text(encoding="utf-8"))
        collector = _AstCollector(repository, compilation_root)
        for entry in database:
            collector.collect(
                _emit_ast(entry, clang, command_prefix, execution_cwd),
                Path(entry.get("directory") or ".") / entry["file"],
            )
        indexes = [
            cls._from_collector(repository, target, paths, collector, aliases=aliases)
            for target, paths in targets.items()
        ]
        return cls(
            declarations=(item for index in indexes for item in index.declarations),
            classes=(item for index in indexes for item in index.classes),
            markers=(item for index in indexes for item in index.markers),
        )

    @classmethod
    def from_ast_documents(
        cls,
        repository: Path,
        target: str,
        source_paths: Sequence[Path],
        documents: Sequence[tuple[dict[str, Any], Path]],
        *,
        aliases: ProjectAliases | None = None,
    ) -> "SourceIndex":
        collector = _AstCollector(repository)
        for document, main_file in documents:
            collector.collect(document, main_file)

        return cls._from_collector(
            repository, target, source_paths, collector, aliases=aliases
        )

    @classmethod
    def from_ast_documents_targets(
        cls,
        repository: Path,
        targets: Mapping[str, Sequence[Path]],
        documents: Sequence[tuple[dict[str, Any], Path]],
        *,
        aliases: ProjectAliases | None = None,
    ) -> "SourceIndex":
        """Bind several marker targets against one already-emitted Clang AST."""

        collector = _AstCollector(repository)
        for document, main_file in documents:
            collector.collect(document, main_file)
        indexes = [
            cls._from_collector(repository, target, paths, collector, aliases=aliases)
            for target, paths in targets.items()
        ]
        return cls(
            declarations=(item for index in indexes for item in index.declarations),
            classes=(item for index in indexes for item in index.classes),
            markers=(item for index in indexes for item in index.markers),
        )

    @classmethod
    def _from_collector(
        cls,
        repository: Path,
        target: str,
        source_paths: Sequence[Path],
        collector: _AstCollector,
        *,
        aliases: ProjectAliases | None = None,
    ) -> "SourceIndex":
        files = tuple(TextFile.from_files(source_paths))
        codebase = DecompCodebase(files, target, aliases=aliases)
        source_files = {
            path.resolve().relative_to(repository.resolve()).as_posix()
            for path in source_paths
        }
        declarations = tuple(
            item
            for item in collector.declarations.values()
            if item.source_file in source_files
        )
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
            if method_symbol.type in {MarkerType.FUNCTION, MarkerType.STUB}:
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
                    marker_name=(
                        method_symbol.name if marker_declaration is None else None
                    ),
                )
            )

        classes = [
            item
            for item in collector.classes.values()
            if item.source_file in source_files
        ]
        classes = [
            replace(
                item,
                asserted_size=collector.size_assertions.get(item.qualified_name),
            )
            for item in classes
        ]
        class_by_location = {
            (item.source_file, item.line): index for index, item in enumerate(classes)
        }
        class_by_name = {
            item.qualified_name: index for index, item in enumerate(classes)
        }
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
                # Template-specialization vtables are commonly accounted for by
                # a standalone class comment instead of a repeated source
                # declaration:
                #
                #   // VTABLE: TARGET 0x1234
                #   // class Vector<Element *>
                #
                # The marker parser already recovers that qualified class name.
                # Bind it to Clang's canonical specialization rather than
                # attaching it positionally to the next class definition.
                index = class_by_name.get(vtable_symbol.name)
            if index is None:
                raise SourceIndexError(
                    f"{relative}:{vtable_symbol.line_number}: VTABLE "
                    f"0x{vtable_symbol.offset:08x} names {vtable_symbol.name}, "
                    "which is not a compiled class definition"
                )
            source_class = classes[index]
            if source_class.vtable_address is not None:
                raise SourceIndexError(
                    f"{relative}:{vtable_symbol.line_number}: class has more than one "
                    "primary VTABLE marker"
                )
            classes[index] = replace(source_class, vtable_address=vtable_symbol.offset)

        return cls(declarations=declarations, classes=classes, markers=markers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "reccmp-source-index-v1",
            "markers": [asdict(item) for item in self.markers],
            "declarations": [asdict(item) for item in self.declarations],
            "classes": [asdict(item) for item in self.classes],
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
