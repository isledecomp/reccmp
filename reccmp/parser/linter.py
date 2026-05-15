from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Sequence
from .parser import DecompParser, ReccmpParserResult
from .error import ParserAlert, ParserError
from .node import ParserFunction, ParserSymbol, ParserString


def get_checkorder_filter(module: str):
    """Return a filter function on implemented functions in the given module"""

    def _filter(sym: ParserSymbol):
        return (
            isinstance(sym, ParserFunction)
            and sym.module == module
            and not sym.lookup_by_name
        )

    return _filter


def file_is_header(filename: PurePath) -> bool:
    return filename.suffix.lower() in (".h", ".hpp")


@dataclass
class PerModuleData:
    addresses: set[int] = field(default_factory=set)
    strings: dict[int, str] = field(default_factory=dict)


class DecompLinter:
    def __init__(self) -> None:
        self.alerts: list[ParserAlert] = []
        self._modules: dict[str, PerModuleData] = {}

    def full_reset(self):
        self._modules.clear()

    def _check_offset_uniqueness(
        self, marker_list: Sequence[ParserSymbol], module: str | None
    ):
        """Helper for loading (module, offset) tuples while the DecompParser
        has them broken up into three different lists."""
        for marker in marker_list:
            # If we are checking a specific module, ignore problems in other modules
            if module is not None and marker.module != module:
                continue

            is_string = isinstance(marker, ParserString)
            is_folded = isinstance(marker, ParserFunction) and marker.is_folded

            if marker.module not in self._modules:
                self._modules[marker.module] = PerModuleData()

            module_data = self._modules[marker.module]

            if marker.offset in module_data.addresses:
                if is_string:
                    existing_string = module_data.strings[marker.offset]
                    if existing_string != marker.name:
                        self.alerts.append(
                            ParserAlert(
                                code=ParserError.WRONG_STRING,
                                line_number=marker.line_number,
                                line=f"0x{marker.offset:08x}, {repr(existing_string)} vs. {repr(marker.name)}",
                                target=module,
                            )
                        )
                elif not is_folded:
                    self.alerts.append(
                        ParserAlert(
                            code=ParserError.DUPLICATE_OFFSET,
                            line_number=marker.line_number,
                            line=f"0x{marker.offset:08x}",
                            target=module,
                        )
                    )
            else:
                module_data.addresses.add(marker.offset)
                if is_string:
                    module_data.strings[marker.offset] = marker.name

    def _check_function_order(self, result: ReccmpParserResult, module: str):
        """Rules:
        1. Only markers that are implemented in the file are considered. This means we
        only look at markers that are cross-referenced with cvdump output by their line
        number. Markers with the lookup_by_name flag set are ignored because we cannot
        directly influence their order.

        2. Order should be considered for a single module only. If we have multiple
        markers for a single function (i.e. for LEGO1 functions linked statically to
        ISLE) then the virtual address space will be very different. If we don't check
        for one module only, we would incorrectly report that the file is out of order.

        3. Functions marked FOLDED are ignored. The ordering is not well understood
        and you may not have much (any?) control over which footprint is used.
        """
        if file_is_header(result.path):
            return

        checkorder_filter = get_checkorder_filter(module)
        last_offset = None
        for fun in filter(checkorder_filter, result.tokens):
            # Skip folded functions altogether.
            # Don't use the address to check the order of any upcoming functions.
            if fun.is_folded:
                continue

            if last_offset is not None:
                if fun.offset < last_offset:
                    self.alerts.append(
                        ParserAlert(
                            code=ParserError.FUNCTION_OUT_OF_ORDER,
                            line_number=fun.line_number,
                            target=module,
                        )
                    )

            last_offset = fun.offset

    def _check_byname_allowed(self, result: ReccmpParserResult):
        if file_is_header(result.path):
            return

        functions = (t for t in result.tokens if isinstance(t, ParserFunction))
        for fun in functions:
            if fun.lookup_by_name:
                self.alerts.append(
                    ParserAlert(
                        code=ParserError.BYNAME_FUNCTION_IN_CPP,
                        line_number=fun.line_number,
                    )
                )

    def read_result(
        self, result: ReccmpParserResult, module: str | None = None
    ) -> bool:
        # The alerts list contains only the linter errors.
        # We used to copy parser syntax errors here.
        self.alerts = []

        self._check_offset_uniqueness(result.tokens, module)
        self._check_byname_allowed(result)

        if module is not None:
            self._check_function_order(result, module)

        return len(self.alerts) == 0

    def read(self, code: str, filename: PurePath, module: str | None = None) -> bool:
        parser = DecompParser()
        parser.reset_and_set_filename(filename)
        parser.read(code)
        parser.finish()
        result = parser.to_result()
        return self.read_result(result, module)
