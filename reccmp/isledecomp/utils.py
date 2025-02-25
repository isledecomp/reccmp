from datetime import datetime
import logging
import colorama
from reccmp.isledecomp.compare.report import ReccmpStatusReport, ReccmpComparedEntity


def print_combined_diff(udiff, plain: bool = False, show_both: bool = False):
    if udiff is None:
        return

    # We don't know how long the address string will be ahead of time.
    # Set this value for each address to try to line things up.
    padding_size = 0

    for slug, subgroups in udiff:
        if plain:
            print("---")
            print("+++")
            print(slug)
        else:
            print(f"{colorama.Fore.RED}---")
            print(f"{colorama.Fore.GREEN}+++")
            print(f"{colorama.Fore.BLUE}{slug}")
            print(colorama.Style.RESET_ALL, end="")

        for subgroup in subgroups:
            equal = subgroup.get("both") is not None

            if equal:
                for orig_addr, line, recomp_addr in subgroup["both"]:
                    padding_size = max(padding_size, len(orig_addr))
                    if show_both:
                        print(f"{orig_addr} / {recomp_addr} : {line}")
                    else:
                        print(f"{orig_addr} : {line}")
            else:
                for orig_addr, line in subgroup["orig"]:
                    padding_size = max(padding_size, len(orig_addr))
                    addr_prefix = (
                        f"{orig_addr} / {'':{padding_size}}" if show_both else orig_addr
                    )

                    if plain:
                        print(f"{addr_prefix} : -{line}")
                    else:
                        print(
                            f"{addr_prefix} : {colorama.Fore.RED}-{line}{colorama.Style.RESET_ALL}"
                        )

                for recomp_addr, line in subgroup["recomp"]:
                    padding_size = max(padding_size, len(recomp_addr))
                    addr_prefix = (
                        f"{'':{padding_size}} / {recomp_addr}"
                        if show_both
                        else " " * padding_size
                    )

                    if plain:
                        print(f"{addr_prefix} : +{line}")
                    else:
                        print(
                            f"{addr_prefix} : {colorama.Fore.GREEN}+{line}{colorama.Style.RESET_ALL}"
                        )

        # Newline between each diff subgroup.
        print()


def print_diff(udiff, plain):
    """Print diff in difflib.unified_diff format."""
    if udiff is None:
        return False

    has_diff = False
    for line in udiff:
        has_diff = True
        color = ""
        if line.startswith("++") or line.startswith("@@") or line.startswith("--"):
            # Skip unneeded parts of the diff for the brief view
            continue
        # Work out color if we are printing color
        if not plain:
            if line.startswith("+"):
                color = colorama.Fore.GREEN
            elif line.startswith("-"):
                color = colorama.Fore.RED
        print(color + line)
        # Reset color if we're printing in color
        if not plain:
            print(colorama.Style.RESET_ALL, end="")
    return has_diff


def get_percent_color(value: float) -> str:
    """Return colorama ANSI escape character for the given decimal value."""
    if value == 1.0:
        return colorama.Fore.GREEN
    if value > 0.8:
        return colorama.Fore.YELLOW

    return colorama.Fore.RED


def percent_string(
    ratio: float, is_effective: bool = False, is_plain: bool = False
) -> str:
    """Helper to construct a percentage string from the given ratio.
    If is_effective (i.e. effective match), indicate that with the asterisk.
    If is_plain, don't use colorama ANSI codes."""

    percenttext = f"{(ratio * 100):.2f}%"
    effective_star = "*" if is_effective else ""

    if is_plain:
        return percenttext + effective_star

    return "".join(
        [
            get_percent_color(ratio),
            percenttext,
            colorama.Fore.RED if is_effective else "",
            effective_star,
            colorama.Style.RESET_ALL,
        ]
    )


def diff_json_display(show_both_addrs: bool = False, is_plain: bool = False):
    """Generate a function that will display the diff according to
    the reccmp display preferences."""

    def formatter(
        orig_addr, saved: ReccmpComparedEntity, new: ReccmpComparedEntity
    ) -> str:
        old_pct = "new"
        new_pct = "gone"
        name = ""
        recomp_addr = "n/a"

        if new is not None:
            new_pct = (
                "stub"
                if new.is_stub
                else percent_string(new.accuracy, new.is_effective_match, is_plain)
            )

            # Prefer the current name of this function if we have it.
            # We are using the original address as the key.
            # A function being renamed is not of interest here.
            name = new.name
            recomp_addr = new.recomp_addr or "n/a"

        if saved is not None:
            old_pct = (
                "stub"
                if saved.is_stub
                else percent_string(saved.accuracy, saved.is_effective_match, is_plain)
            )

            if name == "":
                name = saved.name

        if show_both_addrs:
            addr_string = f"{orig_addr} / {recomp_addr:10}"
        else:
            addr_string = orig_addr

        # The ANSI codes from colorama counted towards string length,
        # so displaying this as an ascii-like spreadsheet
        # (using f-string formatting) would take some effort.
        return f"{addr_string} - {name} ({old_pct} -> {new_pct})"

    return formatter


def diff_json(
    saved_data: ReccmpStatusReport,
    new_data: ReccmpStatusReport,
    show_both_addrs: bool = False,
    is_plain: bool = False,
):
    """Compare two status report files, determine what items changed, and print the result."""

    # Don't try to diff a report generated for a different binary file
    if saved_data.filename != new_data.filename:
        logging.getLogger().error(
            "Diff report for '%s' does not match current file '%s'",
            saved_data.filename,
            new_data.filename,
        )
        return

    if saved_data.timestamp is not None:
        now = datetime.now().replace(microsecond=0)
        then = saved_data.timestamp.replace(microsecond=0)

        print(
            " ".join(
                [
                    "Saved diff report generated",
                    then.strftime("%B %d %Y, %H:%M:%S"),
                    f"({str(now - then)} ago)",
                ]
            )
        )

        print()

    # Convert to dict, using orig_addr as key
    saved_invert = saved_data.entities
    new_invert = new_data.entities

    all_addrs = set(saved_invert.keys()).union(new_invert.keys())

    # Put all the information in one place so we can decide how each item changed.
    combined = {
        addr: (
            saved_invert.get(addr),
            new_invert.get(addr),
        )
        for addr in sorted(all_addrs)
    }

    DiffSubsectionType = dict[
        str, tuple[ReccmpComparedEntity | None, ReccmpComparedEntity | None]
    ]

    # The criteria for diff judgement is in these dict comprehensions:
    # Any function not in the saved file
    new_functions: DiffSubsectionType = {
        key: (saved, new) for key, (saved, new) in combined.items() if saved is None
    }

    # Any function now missing from the saved file
    # or a non-stub -> stub conversion
    dropped_functions: DiffSubsectionType = {
        key: (saved, new)
        for key, (saved, new) in combined.items()
        if new is None
        or (new is not None and saved is not None and new.is_stub and not saved.is_stub)
    }

    # TODO: move these two into functions if the assessment gets more complex
    # Any function with increased match percentage
    # or stub -> non-stub conversion
    improved_functions: DiffSubsectionType = {
        key: (saved, new)
        for key, (saved, new) in combined.items()
        if saved is not None
        and new is not None
        and (new.accuracy > saved.accuracy or (not new.is_stub and saved.is_stub))
    }

    # Any non-stub function with decreased match percentage
    degraded_functions: DiffSubsectionType = {
        key: (saved, new)
        for key, (saved, new) in combined.items()
        if saved is not None
        and new is not None
        and new.accuracy < saved.accuracy
        and not saved.is_stub
        and not new.is_stub
    }

    # Any function with former or current "effective" match
    entropy_functions: DiffSubsectionType = {
        key: (saved, new)
        for key, (saved, new) in combined.items()
        if saved is not None
        and new is not None
        and new.accuracy == 1.0
        and saved.accuracy == 1.0
        and new.is_effective_match != saved.is_effective_match
    }

    get_diff_str = diff_json_display(show_both_addrs, is_plain)

    for diff_name, diff_dict in [
        ("New", new_functions),
        ("Increased", improved_functions),
        ("Decreased", degraded_functions),
        ("Dropped", dropped_functions),
        ("Compiler entropy", entropy_functions),
    ]:
        if len(diff_dict) == 0:
            continue

        print(f"{diff_name} ({len(diff_dict)}):")

        for addr, (saved, new) in diff_dict.items():
            print(get_diff_str(addr, saved, new))

        print()
