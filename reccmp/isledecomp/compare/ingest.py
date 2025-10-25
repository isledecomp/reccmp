"""Part of the core analysis/comparison logic of `reccmp`.
These functions load the entity and type databases with information from code annotations and PDB files.
"""

import logging
from pathlib import Path
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualReadError,
    InvalidStringError,
)
from reccmp.isledecomp.formats.pe import PEImage
from reccmp.isledecomp.cvdump.demangler import (
    demangle_string_const,
)
from reccmp.isledecomp.cvdump import CvdumpTypesParser, CvdumpAnalysis
from reccmp.isledecomp.parser import DecompCodebase
from reccmp.isledecomp.dir import walk_source_dir
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.compare.event import (
    ReccmpEvent,
    ReccmpReportProtocol,
    reccmp_report_nop,
)
from .db import EntityDb, entity_name_from_string
from .lines import LinesDb


logger = logging.getLogger(__name__)


def load_cvdump_types(cvdump_analysis: CvdumpAnalysis, types: CvdumpTypesParser):
    # TODO: Populate the universal type database here when this exists. (#106)
    # For now, just copy the keys into another CvdumpTypesParser so we can use its API.
    types.keys.update(cvdump_analysis.types.keys)


def load_cvdump(cvdump_analysis: CvdumpAnalysis, db: EntityDb, recomp_bin: PEImage):
    # Build the list of entries to insert to the DB.
    # In the rare case we have duplicate symbols for an address, ignore them.
    seen_addrs = set()

    with db.batch() as batch:
        for sym in cvdump_analysis.nodes:
            # Skip nodes where we have almost no information.
            # These probably came from SECTION CONTRIBUTIONS.
            if sym.name() is None and sym.node_type is None:
                continue

            # The PDB might contain sections that do not line up with the
            # actual binary. The symbol "__except_list" is one example.
            # In these cases, just skip this symbol and move on because
            # we can't do much with it.
            if not recomp_bin.is_valid_section(sym.section):
                continue

            addr = recomp_bin.get_abs_addr(sym.section, sym.offset)
            sym.addr = addr

            if addr in seen_addrs:
                continue

            seen_addrs.add(addr)

            # If this symbol is the final one in its section, we were not able to
            # estimate its size because we didn't have the total size of that section.
            # We can get this estimate now and assume that the final symbol occupies
            # the remainder of the section.
            if sym.estimated_size is None:
                sym.estimated_size = (
                    recomp_bin.get_section_extent_by_index(sym.section) - sym.offset
                )

            if sym.node_type == EntityType.STRING:
                assert sym.decorated_name is not None
                string_info = demangle_string_const(sym.decorated_name)
                if string_info is None:
                    logger.debug(
                        "Could not demangle string symbol: %s", sym.decorated_name
                    )
                    continue

                try:
                    # Use the section contribution size if we have it. It is more accurate
                    # than the number embedded in the string symbol:
                    #
                    #     e.g. ??_C@_0BA@EFDM@MxObjectFactory?$AA@
                    #     reported length: 16 (includes null terminator)
                    #     c.f. ??_C@_03DPKJ@enz?$AA@
                    #     reported length: 3 (does NOT include terminator)
                    #
                    # Using a known length enables us to read strings that include null bytes.
                    # string_size is the total memory footprint, including null-terminator.
                    if string_info.is_utf16:
                        if sym.section_contribution is not None:
                            string_size = sym.section_contribution
                            # Remove 2-byte null-terminator before decoding
                            raw = recomp_bin.read(addr, string_size)[:-2]
                        else:
                            raw = recomp_bin.read_widechar(addr)
                            string_size = len(raw) + 2

                        decoded_string = raw.decode("utf-16-le")
                    else:
                        if sym.section_contribution is not None:
                            string_size = sym.section_contribution
                            # Remove 1-byte null-terminator before decoding
                            raw = recomp_bin.read(addr, string_size)[:-1]
                        else:
                            raw = recomp_bin.read_string(addr)
                            string_size = len(raw) + 1

                        decoded_string = raw.decode("latin1")

                except (InvalidVirtualReadError, InvalidStringError):
                    logger.warning(
                        "Could not read string from recomp 0x%x, wide=%s",
                        addr,
                        string_info.is_utf16,
                    )

                except UnicodeDecodeError:
                    logger.warning(
                        "Could not decode string: %s, wide=%s",
                        raw,
                        string_info.is_utf16,
                    )
                    continue

                # Special handling for string entities.
                # Make sure the entity size includes the string null-terminator.
                batch.set_recomp(
                    addr,
                    type=sym.node_type,
                    name=entity_name_from_string(
                        decoded_string, wide=string_info.is_utf16
                    ),
                    symbol=sym.decorated_name,
                    size=string_size,
                    verified=True,
                )
            elif sym.node_type == EntityType.FLOAT:
                # Leave the entity name blank to start. (Don't use the symbol.)
                # We will read the float's value from the binary.
                batch.set_recomp(
                    addr,
                    type=sym.node_type,
                    symbol=sym.decorated_name,
                    size=sym.size(),
                )
            else:
                # Non-string entities.
                batch.set_recomp(
                    addr,
                    type=sym.node_type,
                    name=sym.name(),
                    symbol=sym.decorated_name,
                    size=sym.size(),
                )

                # Set the cvdump type key so it can be referenced later.
                if sym.node_type == EntityType.DATA and sym.data_type is not None:
                    batch.set_recomp(addr, data_type=sym.data_type.key)


def load_cvdump_lines(
    cvdump_analysis: CvdumpAnalysis, lines_db: LinesDb, recomp_bin: PEImage
):
    for filename, values in cvdump_analysis.lines.items():
        lines = [
            (v.line_number, recomp_bin.get_abs_addr(v.section, v.offset))
            for v in values
        ]
        lines_db.add_lines(filename, lines)

    # The seen_addrs set has more than functions, but the intersection of
    # these addrs and the code lines should be just the functions.
    seen_addrs = set(
        # TODO: Ideally this conversion and filtering would happen inside CvdumpAnalysis.
        recomp_bin.get_abs_addr(node.section, node.offset)
        for node in cvdump_analysis.nodes
        if recomp_bin.is_valid_section(node.section)
    )

    lines_db.mark_function_starts(tuple(seen_addrs))


def load_markers(
    code_dir: Path,
    lines_db: LinesDb,
    orig_bin: PEImage,
    target_id: str,
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    codefiles = [Path(p) for p in walk_source_dir(code_dir)]
    lines_db.add_local_paths(codefiles)
    codebase = DecompCodebase(codefiles, target_id)

    # If the address of any annotation would cause an exception,
    # remove it and report an error.
    bad_annotations = codebase.prune_invalid_addrs(orig_bin.is_valid_vaddr)

    for sym in bad_annotations:
        report(
            ReccmpEvent.INVALID_USER_DATA,
            sym.offset,
            msg=f"Invalid address 0x{sym.offset:x} on {sym.type.name} annotation in file: {sym.filename}",
        )

    # Make sure each address is used only once
    duplicate_annotations = codebase.prune_reused_addrs()

    for sym in duplicate_annotations:
        report(
            ReccmpEvent.INVALID_USER_DATA,
            sym.offset,
            msg=f"Dropped duplicate address 0x{sym.offset:x} on {sym.type.name} annotation in file: {sym.filename}",
        )

    # Match lineref functions first because this is a guaranteed match.
    # If we have two functions that share the same name, and one is
    # a lineref, we can match the nameref correctly because the lineref
    # was already removed from consideration.
    with db.batch() as batch:
        for fun in codebase.iter_line_functions():
            batch.set_orig(fun.offset, type=EntityType.FUNCTION, stub=fun.should_skip())

            assert fun.filename is not None
            recomp_addr = lines_db.find_function(
                fun.filename, fun.line_number, fun.end_line
            )

            if recomp_addr is not None:
                batch.match(fun.offset, recomp_addr)

        for fun in codebase.iter_name_functions():
            batch.set_orig(
                fun.offset,
                type=EntityType.FUNCTION,
                stub=fun.should_skip(),
                library=fun.is_library(),
            )

            if fun.name.startswith("?") or fun.name_is_symbol:
                batch.set_orig(fun.offset, symbol=fun.name)
            else:
                batch.set_orig(fun.offset, name=fun.name)

        for var in codebase.iter_variables():
            batch.set_orig(var.offset, name=var.name, type=EntityType.DATA)
            if var.is_static and var.parent_function is not None:
                batch.set_orig(
                    var.offset, static_var=True, parent_function=var.parent_function
                )

        for tbl in codebase.iter_vtables():
            batch.set_orig(
                tbl.offset,
                name=tbl.name,
                base_class=tbl.base_class,
                type=EntityType.VTABLE,
            )

        for string in codebase.iter_strings():
            # Not that we don't trust you, but we're checking the string
            # annotation to make sure it is accurate.
            try:
                if string.is_widechar:
                    string_size = 2 * len(string.name) + 2
                    raw = orig_bin.read(string.offset, string_size)
                    orig = raw.decode("utf-16-le")
                else:
                    string_size = len(string.name) + 1
                    raw = orig_bin.read(string.offset, string_size)
                    orig = raw.decode("latin1")

                string_correct = orig[-1] == "\0" and string.name == orig[:-1]

            except InvalidStringError:
                logger.warning(
                    "Could not read string from orig 0x%x, wide=%s",
                    string.offset,
                    string.is_widechar,
                )
                string_correct = False

            except UnicodeDecodeError:
                logger.warning(
                    "Could not decode string: %s, wide=%s",
                    raw,
                    string.is_widechar,
                )
                string_correct = False

            if not string_correct:
                report(
                    ReccmpEvent.INVALID_USER_DATA,
                    string.offset,
                    msg=f"Data at 0x{string.offset:x} does not match string {repr(string.name)}",
                )
                continue

            batch.set_orig(
                string.offset,
                name=entity_name_from_string(string.name, wide=string.is_widechar),
                type=EntityType.STRING,
                size=string_size,
                verified=True,
            )

        for line in codebase.iter_line_symbols():
            batch.set_orig(
                line.offset,
                name=line.name,
                filename=line.filename,
                line=line.line_number,
                type=EntityType.LINE,
            )
