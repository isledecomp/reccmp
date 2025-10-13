"""Part of the core analysis/comparison logic of `reccmp`.
These functions update the entity database based on analysis of the binary files.
"""

from reccmp.isledecomp.formats.pe import PEImage
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.analysis import (
    find_float_consts,
    find_import_thunks,
    find_vtordisp,
    is_likely_latin1,
)
from .db import EntityDb, entity_name_from_string


def match_entry(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    # The _entry symbol is referenced in the PE header so we get this match for free.
    with db.batch() as batch:
        batch.set_recomp(recomp_bin.entry, type=EntityType.FUNCTION)
        batch.match(orig_bin.entry, recomp_bin.entry)


def find_strings(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    """Search both binaries for Latin1 strings.
    We use the insert_() method so that thse strings will not overwrite
    an existing entity. It's possible that some variables or pointers
    will be mistakenly identified as short strings."""
    with db.batch() as batch:
        for addr, string in orig_bin.iter_string("latin1"):
            # If the address is the site of a relocation, this is a pointer, not a string.
            if addr in orig_bin.relocations:
                continue

            if is_likely_latin1(string) and not db.orig_used(addr):
                batch.set_orig(
                    addr,
                    type=EntityType.STRING,
                    name=entity_name_from_string(string),
                    size=len(string) + 1,  # including null-terminator
                )

        for addr, string in recomp_bin.iter_string("latin1"):
            if addr in recomp_bin.relocations:
                continue

            if is_likely_latin1(string) and not db.recomp_used(addr):
                batch.set_recomp(
                    addr,
                    type=EntityType.STRING,
                    name=entity_name_from_string(string),
                    size=len(string) + 1,  # including null-terminator
                )


def find_float_const(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    """Add floating point constants in each binary to the database.
    We are not matching anything right now because these values are not
    deduped like strings."""
    with db.batch() as batch:
        for addr, size, float_value in find_float_consts(orig_bin):
            if not db.orig_used(addr):
                batch.set_orig(
                    addr, type=EntityType.FLOAT, name=str(float_value), size=size
                )

        for addr, size, float_value in find_float_consts(recomp_bin):
            if not db.recomp_used(addr):
                batch.set_recomp(
                    addr, type=EntityType.FLOAT, name=str(float_value), size=size
                )


def match_imports(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    """We can match imported functions based on the DLL name and
    function symbol name."""
    orig_byaddr = {addr: (dll.upper(), name) for (dll, name, addr) in orig_bin.imports}
    recomp_byname = {
        (dll.upper(), name): addr for (dll, name, addr) in recomp_bin.imports
    }

    with db.batch() as batch:
        for dll, name, addr in orig_bin.imports:
            import_name = f"{dll}::{name}"
            batch.set_orig(
                addr,
                name=import_name,
                size=4,
                type=EntityType.IMPORT,
            )

        for dll, name, addr in recomp_bin.imports:
            import_name = f"{dll}::{name}"
            batch.set_recomp(
                addr,
                name=import_name,
                size=4,
                type=EntityType.IMPORT,
            )

        # Combine these two dictionaries. We don't care about imports from recomp
        # not found in orig because:
        # 1. They shouldn't be there
        # 2. They are already identified via cvdump
        for orig_addr, pair in orig_byaddr.items():
            recomp_addr = recomp_byname.get(pair, None)
            if recomp_addr is not None:
                batch.match(orig_addr, recomp_addr)

    with db.batch() as batch:
        for thunk in find_import_thunks(orig_bin):
            name = f"{thunk.dll_name}::{thunk.func_name}"
            batch.set_orig(
                thunk.addr,
                name=name,
                type=EntityType.FUNCTION,
                skip=True,
                size=thunk.size,
                ref_orig=thunk.import_addr,
            )

        for thunk in find_import_thunks(recomp_bin):
            name = f"{thunk.dll_name}::{thunk.func_name}"
            batch.set_recomp(
                thunk.addr,
                name=name,
                type=EntityType.FUNCTION,
                skip=True,
                size=thunk.size,
                ref_recomp=thunk.import_addr,
            )


def create_thunks(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    """Create entities for any thunk functions in the image.
    These are the result of an incremental build."""
    with db.batch() as batch:
        for orig_thunk, orig_addr in orig_bin.thunks:
            if not db.orig_used(orig_thunk):
                batch.set_orig(
                    orig_thunk,
                    type=EntityType.FUNCTION,
                    size=5,
                    ref_orig=orig_addr,
                    skip=True,
                )

            # We can only match two thunks if we have already matched both
            # their parent entities. There is nothing to compare because
            # they will either be equal or left unmatched. Set skip=True.

        for recomp_thunk, recomp_addr in recomp_bin.thunks:
            if not db.recomp_used(recomp_thunk):
                batch.set_recomp(
                    recomp_thunk,
                    type=EntityType.FUNCTION,
                    size=5,
                    ref_recomp=recomp_addr,
                )


def match_exports(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    # invert for name lookup
    orig_exports = {y: x for (x, y) in orig_bin.exports}

    orig_thunks = dict(orig_bin.thunks)
    recomp_thunks = dict(recomp_bin.thunks)

    with db.batch() as batch:
        for recomp_addr, export_name in recomp_bin.exports:
            orig_addr = orig_exports.get(export_name)
            if orig_addr is None:
                continue

            # Check whether either of the addresses is actually a thunk.
            # This is a quirk of the debug builds. Technically the export
            # *is* the thunk, but it's more helpful to mark the actual function.
            # It could be the case that only one side is a thunk, but we can
            # deal with that.
            if orig_addr in orig_thunks:
                orig_addr = orig_thunks[orig_addr]

            if recomp_addr in recomp_thunks:
                recomp_addr = recomp_thunks[recomp_addr]

            batch.match(orig_addr, recomp_addr)


def match_vtordisp(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    """Find each vtordisp function in each image and match them using
    both the displacement values and the thunk address.

    Should be run after matching all other functions because we depend on
    the thunked functions being matched first.

    PDB does not include the `vtordisp{x, y}' name. We could demangle
    the symbol and get it that way, but instead we just set it here."""

    # Build a reverse mapping from the thunked function and displacement in recomp to the vtordisp address.
    recomp_vtor_reverse = {
        (vt.func_addr, vt.displacement): vt for vt in find_vtordisp(recomp_bin)
    }

    with db.batch() as batch:
        for vtor in find_vtordisp(orig_bin):
            # Follow the link to the thunked function.
            # We want the recomp function addr.
            func = db.get_by_orig(vtor.func_addr)
            if func is None or func.recomp_addr is None:
                continue

            # Now get the recomp vtor reference.
            recomp_vtor = recomp_vtor_reverse.get((func.recomp_addr, vtor.displacement))
            if recomp_vtor is None:
                continue

            # Add the vtordisp name here.
            entity = db.get_by_recomp(recomp_vtor.addr)
            if entity is not None and entity.name is not None:
                new_name = f"{entity.name}`vtordisp{{{recomp_vtor.displacement[0]}, {recomp_vtor.displacement[1]}}}'"
                batch.set_recomp(recomp_vtor.addr, name=new_name)

            batch.match(vtor.addr, recomp_vtor.addr)
