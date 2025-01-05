# (New) Data comparison.

import os
import argparse
import logging
from enum import Enum
from typing import Iterable, NamedTuple
from struct import unpack
import colorama
import reccmp
from reccmp.isledecomp.formats.detect import detect_image
from reccmp.isledecomp.formats.pe import PEImage
from reccmp.isledecomp.compare import Compare as IsleCompare
from reccmp.isledecomp.compare.db import ReccmpMatch
from reccmp.isledecomp.cvdump import Cvdump
from reccmp.isledecomp.cvdump.types import (
    CvdumpKeyError,
    CvdumpIntegrityError,
)
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import (
    RecCmpProjectException,
    RecCmpBuiltTarget,
    argparse_add_built_project_target_args,
    argparse_parse_built_project_target,
)


logger = logging.getLogger(__name__)

colorama.just_fix_windows_console()


# Ignore all compare-db messages.
logging.getLogger("isledecomp.compare").addHandler(logging.NullHandler())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Comparing data values.")
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    argparse_add_built_project_target_args(parser)
    parser.add_argument(
        "-v",
        "--verbose",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )
    parser.add_argument(
        "--all",
        "-a",
        dest="show_all",
        action="store_true",
        help="Only show variables with a problem",
    )
    parser.add_argument(
        "--print-rec-addr",
        action="store_true",
        help="Print addresses of recompiled functions too",
    )
    argparse_add_logging_args(parser)

    args = parser.parse_args()

    argparse_parse_logging(args)
    return args


class CompareResult(Enum):
    MATCH = 1
    DIFF = 2
    ERROR = 3
    WARN = 4


class ComparedOffset(NamedTuple):
    offset: int
    # name is None for scalar types
    name: str | None
    match: bool
    values: tuple[str, str]


class ComparisonItem(NamedTuple):
    """Each variable that was compared"""

    orig_addr: int
    recomp_addr: int
    name: str

    # The list of items that were compared.
    # For a complex type, these are the members.
    # For a scalar type, this is a list of size one.
    # If we could not retrieve type information, this is
    # a list of size one but without any specific type.
    compared: list[ComparedOffset]

    # If present, the error message from the types parser.
    error: str | None = None

    # If true, there is no type specified for this variable. (i.e. non-public)
    # In this case, we can only compare the raw bytes.
    # This is different from the situation where a type id _is_ given, but
    # we could not retrieve it for some reason. (This is an error.)
    raw_only: bool = False

    @property
    def result(self) -> CompareResult:
        if self.error is not None:
            return CompareResult.ERROR

        if all(c.match for c in self.compared):
            return CompareResult.MATCH

        # Prefer WARN for a diff without complete type information.
        return CompareResult.WARN if self.raw_only else CompareResult.DIFF


def create_comparison_item(
    var: ReccmpMatch,
    compared: list[ComparedOffset] | None = None,
    error: str | None = None,
    raw_only: bool = False,
) -> ComparisonItem:
    """Helper to create the ComparisonItem from the fields in the reccmp database."""
    if compared is None:
        compared = []
    assert var.name is not None

    return ComparisonItem(
        orig_addr=var.orig_addr,
        recomp_addr=var.recomp_addr,
        name=var.name,
        compared=compared,
        error=error,
        raw_only=raw_only,
    )


def do_the_comparison(target: RecCmpBuiltTarget) -> Iterable[ComparisonItem]:
    # pylint: disable=too-many-locals
    """Run through each variable in our compare DB, then do the comparison
    according to the variable's type. Emit the result."""
    origfile = detect_image(filepath=target.original_path)
    if not isinstance(origfile, PEImage):
        raise ValueError(f"{target.original_path} is not a PE executable")

    recompfile = detect_image(filepath=target.recompiled_path)
    if not isinstance(recompfile, PEImage):
        raise ValueError(f"{target.recompiled_path} is not a PE executable")

    isle_compare = IsleCompare(
        origfile,
        recompfile,
        target.recompiled_pdb,
        target.source_root,
        target_id=target.target_id,
    )

    # TODO: We don't currently retain the type information of each variable
    # in our compare DB. To get those, we build this mini-lookup table that
    # maps recomp addresses to their type.
    # We still need to build the full compare DB though, because we may
    # need the matched symbols to compare pointers (e.g. on strings)
    mini_cvdump = Cvdump(target.recompiled_pdb).globals().types().run()

    recomp_type_reference = {
        recompfile.get_abs_addr(g.section, g.offset): g.type
        for g in mini_cvdump.globals
        if recompfile.is_valid_section(g.section)
    }

    for var in isle_compare.get_variables():
        assert var.name is not None
        type_name = recomp_type_reference.get(var.recomp_addr)

        # Start by assuming we can only compare the raw bytes
        data_size = var.size
        is_type_aware = type_name is not None

        if is_type_aware:
            try:
                # If we are type-aware, we can get the precise
                # data size for the variable.
                data_type = mini_cvdump.types.get(type_name)
                data_size = data_type.size
            except (CvdumpKeyError, CvdumpIntegrityError) as ex:
                yield create_comparison_item(var, error=repr(ex))
                continue

        assert data_size is not None
        orig_raw = origfile.read(var.orig_addr, data_size)
        recomp_raw = recompfile.read(var.recomp_addr, data_size)

        orig_is_null = all(b == 0 for b in orig_raw)
        recomp_is_null = all(b == 0 for b in recomp_raw)

        # If all bytes are zero on either read, it's possible that the variable
        # is uninitialized on one or both sides. Special handling for that situation:
        if orig_is_null or recomp_is_null:
            # Check the last address of the variable in each file to see if any of it is
            # in the uninitialized area of the section.
            orig_in_bss = origfile.addr_is_uninitialized(var.orig_addr + data_size - 1)
            recomp_in_bss = recompfile.addr_is_uninitialized(
                var.recomp_addr + data_size - 1
            )

            if orig_in_bss or recomp_in_bss:
                # We record a match if both items are null and:
                # 1. Both values are entirely initialized to zero
                # 2. All or part of both values are in the uninitialized area
                match = (
                    orig_is_null and recomp_is_null and (orig_in_bss == recomp_in_bss)
                )

                # However... you may not have full control over where the variable sits in the
                # section, so we will only warn (and not log a diff) if the variable is
                # initialized in one file but not the other.
                uninit_force_match = orig_is_null and recomp_is_null

                orig_value = "(uninitialized)" if orig_in_bss else "(initialized)"
                recomp_value = "(uninitialized)" if recomp_in_bss else "(initialized)"
                yield create_comparison_item(
                    var,
                    compared=[
                        ComparedOffset(
                            offset=0,
                            name=None,
                            match=match,
                            values=(orig_value, recomp_value),
                        )
                    ],
                    raw_only=uninit_force_match,
                )
                continue

        if not is_type_aware:
            # If there is no specific type information available
            # (i.e. if this is a static or non-public variable)
            # then we can only compare the raw bytes.
            yield create_comparison_item(
                var,
                compared=[
                    ComparedOffset(
                        offset=0,
                        name="(raw)",
                        match=orig_raw == recomp_raw,
                        values=(str(orig_raw), str(recomp_raw)),
                    )
                ],
                raw_only=True,
            )
            continue

        # If we are here, we can do the type-aware comparison.
        compared = []
        compare_items = mini_cvdump.types.get_scalars_gapless(type_name)
        format_str = mini_cvdump.types.get_format_string(type_name)

        orig_data = unpack(format_str, orig_raw)
        recomp_data = unpack(format_str, recomp_raw)

        def pointer_display(addr: int, is_orig: bool) -> str:
            """Helper to streamline pointer textual display."""
            if addr == 0:
                return "nullptr"

            ptr_match = (
                isle_compare.get_by_orig(addr)
                if is_orig
                else isle_compare.get_by_recomp(addr)
            )

            if ptr_match is not None:
                return f"Pointer to {ptr_match.match_name()}"

            # This variable did not match if we do not have
            # the pointer target in our DB.
            return f"Unknown pointer 0x{addr:x}"

        # Could zip here
        for i, member in enumerate(compare_items):
            if member.is_pointer:
                match = isle_compare.is_pointer_match(orig_data[i], recomp_data[i])

                value_a = pointer_display(orig_data[i], True)
                value_b = pointer_display(recomp_data[i], False)

                values = (value_a, value_b)
            else:
                match = orig_data[i] == recomp_data[i]
                values = (orig_data[i], recomp_data[i])

            compared.append(
                ComparedOffset(
                    offset=member.offset,
                    name=member.name,
                    match=match,
                    values=values,
                )
            )

        yield create_comparison_item(var, compared=compared)


def value_get(value: str | None, default: str):
    return value if value is not None else default


def main():
    args = parse_args()

    try:
        target = argparse_parse_built_project_target(args=args)
    except RecCmpProjectException as e:
        logger.error(e.args[0])
        return 1

    def display_match(result: CompareResult) -> str:
        """Helper to return color string or not, depending on user preference"""
        if args.no_color:
            return result.name

        match_color = (
            colorama.Fore.GREEN
            if result == CompareResult.MATCH
            else (
                colorama.Fore.YELLOW
                if result == CompareResult.WARN
                else colorama.Fore.RED
            )
        )
        return f"{match_color}{result.name}{colorama.Style.RESET_ALL}"

    var_count = 0
    problems = 0

    for item in do_the_comparison(target):
        var_count += 1
        if item.result in (CompareResult.DIFF, CompareResult.ERROR):
            problems += 1

        if not args.show_all and item.result == CompareResult.MATCH:
            continue

        address_display = (
            f"0x{item.orig_addr:x} / 0x{item.recomp_addr:x}"
            if args.print_rec_addr
            else f"0x{item.orig_addr:x}"
        )

        print(f"{item.name[:80]} ({address_display}) ... {display_match(item.result)} ")
        if item.error is not None:
            print(f"  {item.error}")

        for c in item.compared:
            if not args.verbose and c.match:
                continue

            (value_a, value_b) = c.values
            if c.match:
                print(f"  {c.offset:5} {value_get(c.name, '(value)'):30} {value_a}")
            else:
                print(
                    f"  {c.offset:5} {value_get(c.name, '(value)'):30} {value_a} : {value_b}"
                )

        if args.verbose:
            print()

    print(
        f"{os.path.basename(target.original_path)} - Variables: {var_count}. Issues: {problems}"
    )
    return 0 if problems == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
