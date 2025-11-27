"""Part of the core analysis/comparison logic of `reccmp`.
These functions update the entity database based on analysis of the binary files.
"""

import logging
import struct
from reccmp.isledecomp.formats.pe import PEImage
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.isledecomp.types import EntityType, ImageId
from reccmp.isledecomp.analysis import (
    find_float_consts,
    find_import_thunks,
    find_vtordisp,
    is_likely_latin1,
)
from .db import EntityDb, entity_name_from_string
from .queries import get_floats_without_data


logger = logging.getLogger(__name__)


def match_entry(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    # The _entry symbol is referenced in the PE header so we get this match for free.
    with db.batch() as batch:
        batch.set_recomp(recomp_bin.entry, type=EntityType.FUNCTION)
        batch.match(orig_bin.entry, recomp_bin.entry)


def create_analysis_strings(db: EntityDb, img_id: ImageId, binfile: PEImage):
    """Search both binaries for Latin1 strings.
    We use the insert_() method so that thse strings will not overwrite
    an existing entity. It's possible that some variables or pointers
    will be mistakenly identified as short strings."""
    with db.batch() as batch:
        for addr, string in binfile.iter_string("latin1"):
            # If the address is the site of a relocation, this is a pointer, not a string.
            if addr in binfile.relocations:
                continue

            if is_likely_latin1(string) and not db.used(img_id, addr):
                batch.set(
                    img_id,
                    addr,
                    type=EntityType.STRING,
                    name=entity_name_from_string(string),
                    size=len(string) + 1,  # including null-terminator
                )


def create_analysis_floats(db: EntityDb, img_id: ImageId, binfile: PEImage):
    """Add floating point constants in each binary to the database.
    We are not matching anything right now because these values are not
    deduped like strings."""
    with db.batch() as batch:
        for addr, size, float_value in find_float_consts(binfile):
            if not db.used(img_id, addr):
                batch.set(
                    img_id,
                    addr,
                    type=EntityType.FLOAT,
                    name=str(float_value),
                    size=size,
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
        for image_id, binfile in (
            (ImageId.ORIG, orig_bin),
            (ImageId.RECOMP, recomp_bin),
        ):
            for thunk in find_import_thunks(binfile):
                name = f"{thunk.dll_name}::{thunk.func_name}"
                batch.set(
                    image_id,
                    thunk.addr,
                    name=name,
                    type=EntityType.FUNCTION,
                    skip=True,
                    size=thunk.size,
                )
                batch.set_ref(image_id, thunk.addr, ref=thunk.import_addr)


def create_thunks(db: EntityDb, img_id: ImageId, binfile: PEImage):
    """Create entities for any thunk functions in the image.
    These are the result of an incremental build."""
    with db.batch() as batch:
        for thunk_addr, func_addr in binfile.thunks:
            if not db.used(img_id, thunk_addr):
                batch.set(
                    img_id,
                    thunk_addr,
                    type=EntityType.THUNK,
                    size=5,
                    skip=True,
                )
                batch.set_ref(img_id, thunk_addr, ref=func_addr)

            # We can only match two thunks if we have already matched both
            # their parent entities. There is nothing to compare because
            # they will either be equal or left unmatched. Set skip=True.


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


def create_analysis_vtordisps(db: EntityDb, img_id: ImageId, binfile: PEImage):
    """Creates entities for each detected vtordisp function in the image.
    The critical step is to set the 'vtordisp' attribute to True, which distinguishes
    these entities from others (i.e. thunks) that have the 'ref_' attribute set."""
    with db.batch() as batch:
        for vtor in find_vtordisp(binfile):
            batch.set(
                img_id,
                vtor.addr,
                type=EntityType.VTORDISP,
                size=vtor.size,
            )
            batch.set_ref(
                img_id, vtor.addr, displacement=vtor.displacement, ref=vtor.func_addr
            )

            # Create an entity for the referenced function, but do not overwrite an existing entity (for now).
            if not db.used(img_id, vtor.func_addr):
                batch.set(img_id, vtor.func_addr, type=EntityType.FUNCTION)


def create_partial_floats(db: EntityDb, image_id: ImageId, binfile: PEImage):
    """For each float entity without any data,
    read the value the binary and set the entity name."""
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    with db.batch() as batch:
        for addr, is_double in get_floats_without_data(db, image_id):
            try:
                if is_double:
                    (float_value,) = struct.unpack("<d", binfile.read(addr, 8))
                else:
                    (float_value,) = struct.unpack("<f", binfile.read(addr, 4))

                batch.set(image_id, addr, name=str(float_value))
            except (InvalidVirtualReadError, InvalidVirtualAddressError):
                logger.error(
                    "Failed to read %s from %s at 0x%x",
                    ("double" if is_double else "float"),
                    image_id.name.lower(),
                    addr,
                )
