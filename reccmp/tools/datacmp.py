# (New) Data comparison.

import re
import os
import argparse
import logging
from enum import Enum
from typing import Iterable, NamedTuple
from struct import unpack
from typing_extensions import Self
import colorama
import reccmp
from reccmp.formats import Image
from reccmp.formats.exceptions import InvalidVirtualReadError
from reccmp.compare import Compare
from reccmp.compare.db import ReccmpMatch
from reccmp.cvdump.types import (
    CvdumpKeyError,
    CvdumpIntegrityError,
)
from reccmp.cvdump.cvinfo import CvdumpTypeKey
from reccmp.formats.pe import PEImage
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
logging.getLogger("compare").addHandler(logging.NullHandler())


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


#
# A note about initialized and uninitialized data:
#
# The binary's section header contains the physical and virtual size for each section.
# The physical size corresponds to physical bytes in the file on disk (i.e. the image).
# The virtual size is the actual size of the section in memory. If virtual size is greater than physical
# size, the difference is considered to be uninitialized data. Windows allocates a buffer for the
# virtual size of the section, copies physical data to the start, and sets the remaining bytes to zero.
#
# Reference (PE format):
#     https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
#
# Since the virtual memory for a particular section is made up of both initialized and uninitialized
# data, we can divide it into these regions:
#
# ┌───────────────────────────────────────────────┬─────────────────────────────────┐
# │ Initialized data                              │ Uninitialized data              │
# │ (zero and non-zero bytes)                     │ (Set to zero during image load) │
# └───────────────────────────────────────────────┴─────────────────────────────────┘
#
# Keep in mind: physical size can be zero, meaning the section is entirely uninitialized.
# Physical size can also match or exceed virtual size, meaning the section is fully initialized.
# (The virtual size sets the memory footprint even if physical size is larger.)
#
# Due to the requirement that physical data be aligned to a particular offset, there may be zero bytes
# in the physical data to pad the end of a section where this would otherwise not be necessary.
#
# This means we can subdivide the section further:
#
# ┌───────────────────────────┬───────────────────┬─────────────────────────────────┐
# │ Initialized data          │ Initialized data  │ Uninitialized data              │
# │ (zero and non-zero bytes) │ (only zero bytes) │ (Set to zero during image load) │
# └───────────────────────────┴───────────────────┴─────────────────────────────────┘
#
# Call these memory regions 1, 2, and 3.
#
# A global variable is initialized if its declaration includes an initial value.
#
#     Initialized:   int g_hello = 5;
#   Uninitialized:   int g_hello;
#
# While there is no requirement for a variable to be in a particular spot, we have observed that:
# - Region 1 contains only initialized variables.
# - Region 3 contains only uninitialized variables.
#
# Datacmp will report a diff if a variable resides in region 1 in ORIG and region 3 in RECOMP, or vice versa.
# The user can correct this by providing an initial value or removing it, depending on what ORIG does.
# We cannot make this determination if the variable resides in region 2 in either ORIG or RECOMP.
#


class BssState(Enum):
    """Determination of whether this variable is uninitialized.
    These values correspond to memory regions 1, 2, and 3 in the block comment above.
    BSS refers to a section of memory that is entirely uninitialized.
    - NO:    At least one byte between the variable's start and the
             end of the section is non-zero.
    - MAYBE: The variable is fully initialized to zero. All remaining
             initialized bytes in the section are zero.
    - YES:   All or part of the variable is uninitialized.
    """

    NO = 0
    MAYBE = 1
    YES = 2


class CompareResult(Enum):
    MATCH = 1
    DIFF = 2
    ERROR = 3
    WARN = 4


class DataBlock(NamedTuple):
    addr: int
    data: bytes
    bss: BssState

    @classmethod
    def read(cls, addr: int, size: int, image: Image) -> Self:
        data = image.read(addr, size)
        # Per the seek() API, phys_data is a memoryview of the remaining
        # physical bytes in this section.
        (phys_data, _) = image.seek(addr)

        # If we find any non-zero bytes then this variable must be initialized
        # even if all of the variable's values are zero.
        init_bytes_remain = re.search(b"[^\x00]", phys_data) is not None

        if init_bytes_remain:
            bss = BssState.NO
        elif len(phys_data) < size:
            # If there are not enough physical bytes to cover
            # the entire variable, it is definitely uninitialized.
            bss = BssState.YES
        else:
            # Due to section alignment, there may be enough physical
            # zero bytes to cover this entire variable.
            bss = BssState.MAYBE

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


def pointer_display(compare: Compare, addr: int, is_orig: bool) -> str:
    """Helper to streamline pointer textual display."""
    if addr == 0:
        return "nullptr"

    ptr_match = compare.get_by_orig(addr) if is_orig else compare.get_by_recomp(addr)

    if ptr_match is not None:
        return f"Pointer to {ptr_match.match_name()}"

    # This variable did not match if we do not have
    # the pointer target in our DB.
    return f"Unknown pointer 0x{addr:x}"


def do_the_comparison(target: RecCmpTarget) -> Iterable[ComparisonItem]:
    # pylint: disable=too-many-locals
    """Run through each variable in our compare DB, then do the comparison
    according to the variable's type. Emit the result."""
    compare = Compare.from_target(target)
    origfile = compare.orig_bin
    recompfile = compare.recomp_bin

    if not isinstance(origfile, PEImage) or not isinstance(recompfile, PEImage):
        raise ValueError("`datacmp` currently only supports 32-bit PE images")

    for var in compare.get_variables():
        assert var.name is not None
        type_name = (
            CvdumpTypeKey(var.get("data_type")) if var.get("data_type") else None
        )

        # Start by assuming we can only compare the raw bytes
        data_size = var.size
        raw_only = True

        if type_name is not None:
            try:
                # If we are type-aware, we can get the precise
                # data size for the variable.
                data_type = compare.types.get(type_name)
                assert data_type.size is not None
                data_size = data_type.size

                # Make sure we can retrieve struct or array members.
                if compare.types.get_format_string(type_name):
                    raw_only = False
                else:
                    logger.info(
                        "No struct members for type '0x%x' used by variable '%s' (0x%x). Comparing raw data.",
                        type_name,
                        var.name,
                        var.orig_addr,
                    )

            except (CvdumpKeyError, CvdumpIntegrityError):
                # This may occur even when nothing is wrong, so permit a raw comparison here.
                # For example: we do not handle bitfields and this complicates fieldlist parsing
                # where they are used. (GH #299)
                logger.error(
                    "Could not materialize type '0x%x' used by variable '%s' (0x%x). Comparing raw data.",
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
                DataOffset(offset=i, name="", pointer=False) for i in range(data_size)
            ]
            orig_data = tuple(orig_block.data)
            recomp_data = tuple(recomp_block.data)
        else:
            assert type_name is not None
            compare_items = [
                DataOffset(offset=sc.offset, name=sc.name or "", pointer=sc.is_pointer)
                for sc in compare.types.get_scalars_gapless(type_name)
            ]
            format_str = compare.types.get_format_string(type_name)

            orig_data = unpack(format_str, orig_block.data)
            recomp_data = unpack(format_str, recomp_block.data)

        compared = []
        for orig_val, recomp_val, member in zip(orig_data, recomp_data, compare_items):
            if member.pointer:
                match = compare.is_pointer_match(orig_val, recomp_val)

                value_a = pointer_display(compare, orig_val, True)
                value_b = pointer_display(compare, recomp_val, False)
            else:
                match = orig_val == recomp_val
                value_a = str(orig_val)
                value_b = str(recomp_val)

            # Invalidate the match if there is a definite conflict between
            # the initialized state in orig and recomp.
            if (orig_block.bss == BssState.NO and recomp_block.bss == BssState.YES) or (
                recomp_block.bss == BssState.NO and orig_block.bss == BssState.YES
            ):
                match = False

            if orig_block.bss == BssState.YES:
                value_a = "(uninitialized)"

            if recomp_block.bss == BssState.YES:
                value_b = "(uninitialized)"

            compared.append(
                ComparedOffset(
                    offset=member.offset,
                    name=member.name,
                    match=match,
                    values=(value_a, value_b),
                )
            )

        yield create_comparison_item(
            var,
            compared=compared,
            raw_only=raw_only,
        )


def colorize_match_result(result: CompareResult, no_color: bool) -> str:
    """Helper to return color string or not, depending on user preference"""
    if no_color:
        return result.name

    match result:
        case CompareResult.MATCH:
            color = colorama.Fore.GREEN
        case CompareResult.ERROR | CompareResult.DIFF:
            color = colorama.Fore.RED
        case _:
            color = colorama.Fore.YELLOW

    return f"{color}{result.name}{colorama.Style.RESET_ALL}"


def compared_offset_string(c: ComparedOffset, no_color: bool) -> str:
    """Display the offset, name, and value diff for each compared item.
    Scalar variables have only a single item, the value itself."""

    def ansi_wrap(c: str):
        """Easily remove the ANSI codes in --no-color mode."""
        return "" if no_color else c

    offset = f"+ 0x{c.offset:02x}"
    header_chunk = [ansi_wrap(colorama.Fore.LIGHTBLACK_EX), f"{offset:>10}"]

    name_chunk = [
        ": " if c.name else "  ",
        ansi_wrap(colorama.Fore.WHITE),
        f"{c.name if c.name else '':30}",
    ]

    (value_a, value_b) = c.values
    values_chunk = [ansi_wrap(colorama.Fore.LIGHTWHITE_EX), value_a]
    if not c.match:
        values_chunk.extend([" : ", ansi_wrap(colorama.Fore.LIGHTBLACK_EX), value_b])

    return " ".join(
        [
            "".join(header_chunk),
            "".join(name_chunk),
            "".join(values_chunk),
            ansi_wrap(colorama.Style.RESET_ALL),
        ]
    )


def main():
    args = parse_args()

    try:
        target = argparse_parse_project_target(args=args)
    except RecCmpProjectException as e:
        logger.error(e.args[0])
        return 1

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

        print(
            f"{item.name[:80]} ({address_display}) ... {colorize_match_result(item.result, args.no_color)} "
        )
        if item.error is not None:
            print(f"  {item.error}")

        if item.raw_only:
            print("  Unknown or unsupported data type, comparing raw data only.")

        for c in item.compared:
            if not args.verbose and c.match:
                continue

            print(compared_offset_string(c, args.no_color))

        if args.verbose:
            print()

    print(
        f"{os.path.basename(target.original_path)} - Variables: {var_count}. Issues: {problems}"
    )
    return 0 if problems == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
