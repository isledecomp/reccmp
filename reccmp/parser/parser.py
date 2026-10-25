# C++ file parser

import io
from dataclasses import dataclass
from pathlib import PurePath
from typing import Iterator
from .util import (
    get_class_name,
    get_variable_name,
    unwrap_line_comment,
    get_string_contents,
)
from .marker import (
    MARKER_CATEGORY_MAP,
    DecompMarker,
    MarkerCategory,
    MarkerType,
    is_marker_exact,
    ProjectAliases,
    match_marker,
    marker_options,
    markerRegex,
    split_duplicates,
)
from .node import (
    ParserLineSymbol,
    ParserSymbol,
    ParserFunction,
    ParserVariable,
    ParserVtable,
    ParserString,
)
from .error import ParserAlert, AlertCode
from .tokenizer import (
    all_curly_paired,
    CodeToken,
    resolve_preprocessor,
    get_line_column_pos,
    get_newlines_from_text,
    get_namespaces_from_scopes,
    get_string_from_ppc,
    get_blank_lines_in_range,
    resolve_scopes,
    tokenize_code_file,
    TokenType,
)


@dataclass(frozen=True)
class ReccmpParserResult:
    tokens: tuple[ParserSymbol, ...]
    alerts: tuple[ParserAlert, ...]
    path: PurePath


class DecompParser:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, aliases: ProjectAliases | None = None) -> None:
        # The lists to be populated as we parse
        self._symbols: list[ParserSymbol] = []
        self.alerts: list[ParserAlert] = []

        self.filename: PurePath = PurePath("")

        self.aliases = aliases or {}

        self.newlines: list[int] = []
        self.enclosures: dict[int, int] = {}
        self.namespaces: list[tuple[int, int, str, str]] = []
        """Ranges and names of namespaces in the current file, given as: (start, end, keyword, name)"""

        self.seen_functions: dict[str, list[tuple[int, range]]] = {}

    def reset_and_set_filename(self, filename: PurePath):
        self._symbols = []
        self.alerts = []

        self.filename = filename

        self.newlines = []
        self.enclosures.clear()
        self.namespaces.clear()
        self.seen_functions.clear()

    def _qualify(self, name: str | None, pos: int) -> str:
        """Qualify the provided name with the combined scope names for our current file position."""
        namespaces = [
            name for start, stop, _, name in self.namespaces if start < pos < stop
        ]
        if not namespaces:
            return name or ""

        if name is not None and name not in namespaces:
            namespaces.append(name)

        return "::".join(namespaces)

    @property
    def functions(self) -> list[ParserFunction]:
        return [s for s in self._symbols if isinstance(s, ParserFunction)]

    @property
    def vtables(self) -> list[ParserVtable]:
        return [s for s in self._symbols if isinstance(s, ParserVtable)]

    @property
    def variables(self) -> list[ParserVariable]:
        return [s for s in self._symbols if isinstance(s, ParserVariable)]

    @property
    def strings(self) -> list[ParserString]:
        return [s for s in self._symbols if isinstance(s, ParserString)]

    @property
    def lines(self) -> list[ParserLineSymbol]:
        return [s for s in self._symbols if isinstance(s, ParserLineSymbol)]

    def iter_symbols(self, module: str | None = None) -> Iterator[ParserSymbol]:
        for s in self._symbols:
            if module is None or s.module == module:
                yield s

    def _alert(self, code: AlertCode, pos: int = -1, text: str = ""):
        line_no, _ = get_line_column_pos(self.newlines, pos)
        self.alerts.append(
            ParserAlert(
                path=self.filename,
                line_number=line_no,
                code=code,
                detail=text.strip(),
            )
        )

    def _select_markers(
        self, markers: list[DecompMarker]
    ) -> list[tuple[MarkerCategory, list[DecompMarker]]]:
        """Select markers that will be finalized into annotations.
        Markers are grouped by the expected completion token."""
        groups: dict[MarkerCategory, list[DecompMarker]] = {}

        # 1. Group into categories, reject unknown marker types.
        for marker in markers:
            category = MARKER_CATEGORY_MAP[marker.type]
            if category == MarkerCategory.UNKNOWN:
                self._alert(AlertCode.UNKNOWN_ANNOTATION, marker.pos)
                continue

            groups.setdefault(category, []).append(marker)

        # 2. Reject all markers if any categories are in conflict.
        clash_types = {c for c in groups if c != MarkerCategory.LINE}
        if len(clash_types) > 1 and not clash_types <= {
            MarkerCategory.VARIABLE,
            MarkerCategory.STRING,
        }:
            for category in clash_types:
                for marker in groups[category]:
                    self._alert(AlertCode.INCOMPATIBLE_MARKER, marker.pos)

                del groups[category]

        # 3. Reject markers that are duplicates from the same module.
        output = []
        for category, group in groups.items():
            valid, duplicates = split_duplicates(category, group)
            for marker in duplicates:
                self._alert(AlertCode.DUPLICATE_MODULE, marker.pos)

            output.append((category, valid))

        return output

    def _finish_name_function(
        self,
        markers: list[DecompMarker],
        function_name: str,
        pos: int,
    ):
        # Same line: derived from line comment
        start_line, _ = get_line_column_pos(self.newlines, pos)

        marker_types = {
            marker.type for marker in markers if marker.type != MarkerType.STUB
        }

        for marker in markers:
            if marker.type != MarkerType.STUB and len(marker_types) > 1:
                self._alert(AlertCode.VARYING_MARKER_TYPES, marker.pos)

            options = marker_options(marker)
            name_is_symbol = options["SYMBOL"]
            is_folded = options["FOLDED"]

            self._symbols.append(
                ParserFunction(
                    type=marker.type,
                    line_number=start_line,
                    module=marker.module,
                    offset=marker.offset,
                    name=function_name,
                    filename=self.filename,
                    lookup_by_name=True,
                    name_is_symbol=name_is_symbol,
                    end_line=start_line,
                    is_folded=is_folded,
                )
            )

    def _finish_line_function(
        self,
        markers: list[DecompMarker],
        start: int,
        end: int,
    ):
        start_line, _ = get_line_column_pos(self.newlines, start)
        end_line, _ = get_line_column_pos(self.newlines, end)

        for marker in markers:
            if marker.type in {
                MarkerType.SYNTHETIC,
                MarkerType.TEMPLATE,
                MarkerType.LIBRARY,
            }:
                self._alert(AlertCode.BAD_NAMEREF, marker.pos)
                continue

            options = marker_options(marker)

            if options["SYMBOL"]:
                self._alert(AlertCode.SYMBOL_OPTION_IGNORED, marker.pos)

            is_folded = options["FOLDED"]

            self.seen_functions.setdefault(marker.module, []).insert(
                0, (marker.offset, range(start, end + 1))
            )

            self._symbols.append(
                ParserFunction(
                    type=marker.type,
                    line_number=start_line,
                    module=marker.module,
                    offset=marker.offset,
                    name="",  # This was never accurate
                    filename=self.filename,
                    lookup_by_name=False,
                    name_is_symbol=False,
                    end_line=end_line,
                    is_folded=is_folded,
                )
            )

    def _finish_string(
        self, markers: list[DecompMarker], text: str, is_widechar: bool, pos: int
    ):
        line_number, _ = get_line_column_pos(self.newlines, pos)

        for marker in markers:
            self._symbols.append(
                ParserString(
                    type=marker.type,
                    line_number=line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=text,
                    filename=self.filename,
                    is_widechar=is_widechar,
                )
            )

    def _find_function_for_static(self, module: str, pos: int) -> int | None:
        functions = self.seen_functions.get(module, [])
        for func_addr, func_span in functions:
            if pos in func_span:
                return func_addr

        return None

    def _finish_variable(
        self,
        markers: list[DecompMarker],
        variable_name: str,
        pos: int,
    ):
        line_number, _ = get_line_column_pos(self.newlines, pos)

        parent_functions = {}
        for marker in markers:
            func_addr = self._find_function_for_static(marker.module, marker.pos)
            if func_addr:
                parent_functions[marker.module] = func_addr

        # If any are defined
        is_static = bool(parent_functions)

        for marker in markers:
            qualified_name = self._qualify(variable_name, marker.pos)

            parent_function = None
            if is_static:
                if marker.module in parent_functions:
                    parent_function = parent_functions[marker.module]
                else:
                    self._alert(AlertCode.ORPHANED_STATIC_VARIABLE, marker.pos)
                    continue

            self._symbols.append(
                ParserVariable(
                    type=marker.type,
                    line_number=line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=qualified_name,
                    filename=self.filename,
                    is_static=is_static,
                    parent_function=parent_function,
                )
            )

    def _finish_vtable(
        self,
        markers: list[DecompMarker],
        class_name: str,
        pos: int,
    ):
        line_number, _ = get_line_column_pos(self.newlines, pos)

        for marker in markers:
            qualified_name = self._qualify(class_name, marker.pos)

            options = marker_options(marker)
            base_class = options["BASE_CLASS"]
            is_folded = options["FOLDED"]

            self._symbols.append(
                ParserVtable(
                    type=marker.type,
                    line_number=line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=qualified_name,
                    filename=self.filename,
                    base_class=base_class,
                    is_folded=is_folded,
                )
            )

    def _finish_line(self, markers: list[DecompMarker]):
        for marker in markers:
            line_number, _ = get_line_column_pos(self.newlines, marker.pos)
            self._symbols.append(
                ParserLineSymbol(
                    type=marker.type,
                    line_number=line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=f"{self.filename.name}:{line_number}",
                    filename=self.filename,
                )
            )

    def _code_vtable(
        self,
        text: str,
        candidates: list[CodeToken],
        markers: list[DecompMarker],
    ):
        failure_code = AlertCode.NO_SUITABLE_NAME

        for start, stop, token in candidates:
            if token == TokenType.LINE_COMMENT:
                excerpt = text[start:stop]
                vtable_class = get_class_name(excerpt)
                if vtable_class is not None:
                    self._finish_vtable(markers, vtable_class, start)
                    return

                # Don't break so we skip past `// SIZE` comments.
                # TODO: Skip "SIZE" specifically?

            elif token == TokenType.CURLY_OPEN:
                # Use existing named scope parsing.
                for scope_start, _, keyword, class_name in self.namespaces:
                    if scope_start == start and keyword != "namespace":
                        self._finish_vtable(markers, class_name, start)
                        return

                break

            elif token == TokenType.SEMICOLON:
                break

        # Did not find the completion token.
        for marker in markers:
            self._alert(failure_code, marker.pos)

    def _code_function(
        self,
        text: str,
        candidates: list[CodeToken],
        markers: list[DecompMarker],
    ):
        found_sig = False
        sig_pos = 0
        failure_code = AlertCode.MISSED_START_OF_FUNCTION

        for start, stop, token in candidates:
            if token == TokenType.CODE:
                if not found_sig:
                    # Use the position from the first CODE token.
                    # Args may be split by an equal sign (default param)
                    # or by inline comments.
                    found_sig = True
                    sig_pos = start

            if token == TokenType.LINE_COMMENT and not found_sig:
                # Allow comments between signature and curly bracket.
                # e.g. `vtable+0x08`
                excerpt = text[start:stop]
                synthetic_name = unwrap_line_comment(excerpt)
                if synthetic_name:
                    self._finish_name_function(markers, synthetic_name, start)
                    return

                failure_code = AlertCode.NO_SUITABLE_NAME
                break

            if token == TokenType.SEMICOLON:
                if found_sig:
                    failure_code = AlertCode.NO_IMPLEMENTATION

                break

            if token == TokenType.CURLY_OPEN:
                if not found_sig:
                    break

                if start not in self.enclosures:
                    break

                func_end = self.enclosures[start]
                self._finish_line_function(markers, sig_pos, func_end)
                return

            if token == TokenType.CURLY_CLOSE:
                # Make sure we abort as to not match with a subsequent curly bracket.
                break

        # Did not find the completion token.
        for marker in markers:
            self._alert(failure_code, marker.pos)

    def _code_variable(
        self,
        text: str,
        candidates: list[CodeToken],
        markers: list[DecompMarker],
    ):
        variable_name = None
        failure_code = AlertCode.NO_SUITABLE_NAME

        for start, stop, token in candidates:
            excerpt = text[start:stop]

            if token == TokenType.CODE:
                variable_name = get_variable_name(excerpt)
                if variable_name:
                    if excerpt.startswith("return"):
                        # TODO: New alert code? (GH #598)
                        failure_code = AlertCode.GLOBAL_NOT_VARIABLE
                        break

                    self._finish_variable(markers, variable_name, start)
                    return

                failure_code = AlertCode.GLOBAL_NOT_VARIABLE
                break

            if token == TokenType.LINE_COMMENT:
                variable_name = unwrap_line_comment(excerpt)
                if variable_name:
                    self._finish_variable(markers, variable_name, start)
                    return

            # It must be one of those two token types.
            break

        # Did not find the completion token.
        for marker in markers:
            self._alert(failure_code, marker.pos)

    def _code_string(
        self,
        text: str,
        candidates: list[CodeToken],
        markers: list[DecompMarker],
    ):
        failure_code = AlertCode.STRING_NOT_FOUND

        for start, stop, token in candidates:
            if token == TokenType.STRING:
                excerpt = text[start:stop]
                string_obj = get_string_contents(excerpt)

                if string_obj:
                    self._finish_string(
                        markers, string_obj.text, string_obj.is_widechar, start
                    )
                    return

                break

            if token == TokenType.LINE_COMMENT:
                excerpt = text[start:stop]
                string_text = unwrap_line_comment(excerpt)
                if not string_text:
                    failure_code = AlertCode.NO_SUITABLE_NAME
                    break

                string_obj = get_string_contents(string_text)

                if string_obj:
                    self._finish_string(
                        markers, string_obj.text, string_obj.is_widechar, start
                    )
                    return

                break

            if token == TokenType.PPC_OTHER:
                # Read the first string found in the #define token.
                string_token = get_string_from_ppc(text, start, stop)
                if string_token is not None:
                    self._code_string(text, [string_token], markers)
                    return

                break

            if token == TokenType.SEMICOLON:
                break

        # Did not find the completion token.
        for marker in markers:
            self._alert(failure_code, marker.pos)

    def _get_marker_sets(
        self, tokens: list[CodeToken], possible_markers: dict[int, tuple[str, ...]]
    ) -> list[tuple[list[DecompMarker], list[CodeToken]]]:
        markers: list[DecompMarker] = []
        candidates: list[CodeToken] = []
        output = []

        for x in tokens:
            if x[0] in possible_markers:
                # If we have begun reading candidates, this is the end of this group.
                if candidates:
                    output.append((markers, candidates))
                    markers = []
                    candidates = []

                markers.append(
                    match_marker(x[0], x[1], possible_markers[x[0]], self.aliases)
                )
            elif markers:
                # Only add if we have read any markers.
                candidates.append(x)

        if markers:
            output.append((markers, candidates))

        return output

    def _check_marker_format(self, text: str, markers: list[DecompMarker]):
        for marker in markers:
            if not is_marker_exact(text, marker.pos):
                self._alert(
                    AlertCode.NOT_STRICT_FORMAT,
                    marker.pos,
                    text[marker.pos : marker.endpos],
                )

    def _report_blank_lines(self, text: str, markers: list[DecompMarker], end: int):
        """Warn for blank lines between any markers in a sequence, or between the last marker
        and the next token. Markers that do not need a completion token (e.g. LINE) are exempt.
        `end` is the position of the next token following any whitespace."""

        # Find the first marker that requires a completion token.
        # Once that sequence of markers begins, report blank lines between any marker.
        start = next((m.pos for m in markers if m.type != MarkerType.LINE), None)
        if start is None:
            return

        for blank_line in get_blank_lines_in_range(self.newlines, text, start, end):
            self._alert(AlertCode.UNEXPECTED_BLANK_LINE, blank_line)

    def read(self, raw_text: str):
        # The tokenizer expects that newlines are a single char: `\n`.
        # Make sure that's what we have.
        text = io.StringIO(raw_text, newline=None).read()

        # Performance: skip the expensive token operations if there are no markers in the file.
        possible_markers = {m.start(): m.groups() for m in markerRegex.finditer(text)}
        if not possible_markers:
            return

        # Find the boundaries of all scopes now so we do not need to keep the stack
        # up to date while reading.
        raw_tokens = tokenize_code_file(text)
        tokens = resolve_preprocessor(raw_tokens, text)
        self.newlines = get_newlines_from_text(text)
        self.enclosures, remain = resolve_scopes(tokens)
        if not all_curly_paired(remain):
            self._alert(AlertCode.CURLY_BRACKET_IMBALANCE, 0)

        self.namespaces = get_namespaces_from_scopes(text, tokens, self.enclosures)

        # Split the tokens into regions of marker tokens and "candidate" completion tokens.
        for marker_set, candidates in self._get_marker_sets(tokens, possible_markers):
            self._check_marker_format(text, marker_set)

            # Report blank lines between markers in the set and the first candidate completion token.
            # If there are no candidates, check up to the last marker.
            end = candidates[0][0] if candidates else marker_set[-1].pos
            self._report_blank_lines(text, marker_set, end)

            # Select the markers we will try to complete.
            # Discard markers that cannot be combined in a group.
            # e.g. FUNCTION + GLOBAL
            for category, markers in self._select_markers(marker_set):
                if category == MarkerCategory.FUNCTION:
                    self._code_function(text, candidates, markers)

                elif category == MarkerCategory.VTABLE:
                    self._code_vtable(text, candidates, markers)

                elif category == MarkerCategory.VARIABLE:
                    self._code_variable(text, candidates, markers)

                elif category == MarkerCategory.STRING:
                    self._code_string(text, candidates, markers)

                elif category == MarkerCategory.LINE:
                    self._finish_line(markers)

    def to_result(self) -> ReccmpParserResult:
        return ReccmpParserResult(
            tuple(self._symbols), tuple(self.alerts), self.filename
        )
