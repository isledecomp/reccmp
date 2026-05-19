from pathlib import PurePath
from typing import Iterator, Sequence
from .parser import ReccmpParserResult
from .error import AlertCode, ParserAlert
from .node import ParserFunction, ParserString


def file_is_header(path: PurePath) -> bool:
    return path.suffix.lower() in (".h", ".hpp")


def check_byname_allowed(result: ReccmpParserResult) -> list[ParserAlert]:
    if file_is_header(result.path):
        return []

    alerts = []

    for fun in result.tokens:
        if isinstance(fun, ParserFunction) and fun.lookup_by_name:
            alerts.append(
                ParserAlert(
                    code=AlertCode.BYNAME_FUNCTION_IN_CPP,
                    path=result.path,
                    line_number=fun.line_number,
                )
            )

    return alerts


def check_function_order(result: ReccmpParserResult) -> list[ParserAlert]:
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
        return []

    alerts = []

    relevant_markers = (
        marker
        for marker in result.tokens
        if isinstance(marker, ParserFunction) and not marker.lookup_by_name
    )

    # The most recent address for each module.
    last_offset: dict[str, int] = {}

    for fun in relevant_markers:
        # Skip folded functions altogether.
        # Don't use the address to check the order of any upcoming functions.
        if fun.is_folded:
            continue

        if fun.module in last_offset and fun.offset < last_offset[fun.module]:
            alerts.append(
                ParserAlert(
                    code=AlertCode.FUNCTION_OUT_OF_ORDER,
                    path=result.path,
                    line_number=fun.line_number,
                    target=fun.module,
                )
            )

        last_offset[fun.module] = fun.offset

    return alerts


def check_offset_uniqueness(results: Sequence[ReccmpParserResult]) -> list[ParserAlert]:
    alerts = []
    seen_addresses: dict[str, set[int]] = {}

    for result in results:
        for marker in result.tokens:
            is_folded = isinstance(marker, ParserFunction) and marker.is_folded
            is_string = isinstance(marker, ParserString)

            module_addresses = seen_addresses.setdefault(marker.module, set())

            if marker.offset in module_addresses and not is_folded and not is_string:
                alerts.append(
                    ParserAlert(
                        code=AlertCode.DUPLICATE_OFFSET,
                        path=result.path,
                        line_number=marker.line_number,
                        line=f"0x{marker.offset:08x}",
                        target=marker.module,
                    )
                )
            else:
                module_addresses.add(marker.offset)

    return alerts


def check_string_text(results: Sequence[ReccmpParserResult]) -> list[ParserAlert]:
    alerts = []
    seen_strings: dict[str, dict[int, str]] = {}

    for result in results:
        relevant_markers = (
            marker for marker in result.tokens if isinstance(marker, ParserString)
        )

        for marker in relevant_markers:
            module_strings = seen_strings.setdefault(marker.module, {})

            if marker.offset in module_strings:
                existing_string = module_strings[marker.offset]
                if existing_string != marker.name:
                    alerts.append(
                        ParserAlert(
                            code=AlertCode.WRONG_STRING,
                            path=result.path,
                            line_number=marker.line_number,
                            line=f"0x{marker.offset:08x}, {repr(existing_string)} vs. {repr(marker.name)}",
                            target=marker.module,
                        )
                    )
            else:
                module_strings[marker.offset] = marker.name

    return alerts


def lint_file_collections(
    results: Sequence[ReccmpParserResult], module: str | None
) -> Iterator[ParserAlert]:
    def module_filter(alert: ParserAlert) -> bool:
        return module is None or alert.target == module

    yield from filter(module_filter, check_offset_uniqueness(results))
    yield from filter(module_filter, check_string_text(results))
