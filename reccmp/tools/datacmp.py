# (New) Data comparison.

import os
import argparse
import logging
from enum import Enum
from typing import Iterable, NamedTuple
from struct import unpack
from typing_extensions import Self
import colorama
import reccmp
from reccmp.isledecomp.formats import Image
from reccmp.isledecomp.formats.exceptions import InvalidVirtualReadError
from reccmp.isledecomp.compare import Compare as IsleCompare
from reccmp.isledecomp.compare.db import ReccmpMatch
from reccmp.isledecomp.cvdump.types import (
    CvdumpKeyError,
    CvdumpIntegrityError,
)
from reccmp.isledecomp.formats.pe import PEImage
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging
from reccmp.project.detect import (
    RecCmpProjectException,
    RecCmpTarget,
    argparse_add_project_target_args,
    argparse_parse_project_target,
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
    argparse_add_project_target_args(parser)
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


class DataBlock(NamedTuple):
    addr: int
    data: bytes
    bss: bool

    @classmethod
    def read(cls, addr: int, size: int, image: Image) -> Self:
        data = image.read(addr, size)
        (phys_data, _) = image.seek(addr)
        bss = len(phys_data) < size

        return cls(addr, data, bss)


class DataOffset(NamedTuple):
    offset: int
    name: str
    pointer: bool


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

    bss: tuple[bool, bool] = (False, False)

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
    bss: tuple[bool, bool] = (False, False),
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
        bss=bss,
    )


def pointer_display(isle_compare: IsleCompare, addr: int, is_orig: bool) -> str:
    """Helper to streamline pointer textual display."""
    if addr == 0:
        return "nullptr"

    ptr_match = (
        isle_compare.get_by_orig(addr) if is_orig else isle_compare.get_by_recomp(addr)
    )

    if ptr_match is not None:
        return f"Pointer to {ptr_match.match_name()}"

    # This variable did not match if we do not have
    # the pointer target in our DB.
    return f"Unknown pointer 0x{addr:x}"


def do_the_comparison(target: RecCmpTarget) -> Iterable[ComparisonItem]:
    # pylint: disable=too-many-locals
    """Run through each variable in our compare DB, then do the comparison
    according to the variable's type. Emit the result."""
    isle_compare = IsleCompare.from_target(target)
    origfile = isle_compare.orig_bin
    recompfile = isle_compare.recomp_bin

    if not isinstance(origfile, PEImage) or not isinstance(recompfile, PEImage):
        raise ValueError("`datacmp` currently only supports 32-bit PE images")

    for var in isle_compare.get_variables():
        assert var.name is not None
        type_name = var.get("data_type")

        # Start by assuming we can only compare the raw bytes
        data_size = var.size
        raw_only = True

        if type_name is not None:
            try:
                # If we are type-aware, we can get the precise
                # data size for the variable.
                data_type = isle_compare.types.get(type_name)
                assert data_type.size is not None
                data_size = data_type.size

                # Make sure we can retrieve struct or array members.
                if isle_compare.types.get_format_string(type_name):
                    raw_only = False

            except (CvdumpKeyError, CvdumpIntegrityError):
                # TODO: This may occur even when nothing is wrong, so permit a raw comparison here.
                # For example: we do not handle bitfields and this complicates fieldlist parsing
                # where they are used.
                logger.error(
                    "Could not materialize type key '%s' for variable '%s' at 0x%x. Comparing raw data.",
                    type_name,
                    var.name,
                    var.orig_addr,
                )

        assert data_size is not None

        try:
            orig_block = DataBlock.read(var.orig_addr, data_size, origfile)
        except InvalidVirtualReadError as ex:
            # Reading from orig can fail if the recomp variable is too large
            yield create_comparison_item(var, error=repr(ex))
            continue

        # Reading from recomp should never fail, so if it does, raising an exception is correct
        recomp_block = DataBlock.read(var.recomp_addr, data_size, recompfile)

        if raw_only:
            # If there is no specific type information available
            # (i.e. if this is a static or non-public variable)
            # then we can only compare the raw bytes.
            compare_items = [
                DataOffset(offset=i, name=f"[{i}]", pointer=False)
                for i in range(data_size)
            ]
            orig_data = tuple(orig_block.data)
            recomp_data = tuple(recomp_block.data)
        else:
            compare_items = [
                DataOffset(offset=sc.offset, name=sc.name or "", pointer=sc.is_pointer)
                for sc in isle_compare.types.get_scalars_gapless(type_name)
            ]
            format_str = isle_compare.types.get_format_string(type_name)

            orig_data = unpack(format_str, orig_block.data)
            recomp_data = unpack(format_str, recomp_block.data)

        # Could zip here
        compared = []
        for i, member in enumerate(compare_items):
            if member.pointer:
                match = isle_compare.is_pointer_match(orig_data[i], recomp_data[i])

                value_a = pointer_display(isle_compare, orig_data[i], True)
                value_b = pointer_display(isle_compare, recomp_data[i], False)

                values = (value_a, value_b)
            else:
                match = orig_data[i] == recomp_data[i]
                values = (str(orig_data[i]), str(recomp_data[i]))

            compared.append(
                ComparedOffset(
                    offset=member.offset,
                    name=member.name,
                    match=match,
                    values=values,
                )
            )

        yield create_comparison_item(
            var,
            compared=compared,
            raw_only=raw_only,
            bss=(orig_block.bss, recomp_block.bss),
        )


def value_get(value: str | None, default: str):
    return value if value is not None else default


def main():
    args = parse_args()

    try:
        target = argparse_parse_project_target(args=args)
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

        if item.raw_only:
            print("  Comparing raw data only.")

        if item.bss[0] != item.bss[1]:
            if item.bss[0]:
                print("  Recomp should be uninitialized.")
            else:
                print("  Recomp should have initial value.")

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
