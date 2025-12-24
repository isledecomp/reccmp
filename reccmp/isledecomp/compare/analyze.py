"""Part of the core analysis/comparison logic of `reccmp`.
These functions update the entity database based on analysis of the binary files.
"""

import logging
import struct
from reccmp.isledecomp.formats import Image, PEImage
from reccmp.isledecomp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
    InvalidStringError,
)
from reccmp.isledecomp.types import EntityType, ImageId
from reccmp.isledecomp.analysis import (
    find_float_consts,
    find_import_thunks,
    find_vtordisp,
    find_eh_handlers,
    is_likely_latin1,
)
from .db import EntityDb, entity_name_from_string
from .queries import get_floats_without_data, get_strings_without_data


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


def create_seh_entities(db: EntityDb, img_id: ImageId, binfile: PEImage):
    """Create entities for the SEH (structured exception handling)
    handler and funcinfo struct. For images without a relocation table,
    this will allow us to replace the addresses for both items."""
    with db.batch() as batch:
        for handler_addr, funcinfo in find_eh_handlers(binfile):
            # Using names derived from symbols in .cpp.s generated asm.
            batch.set(
                img_id,
                handler_addr,
                type=EntityType.LABEL,
                name="__ehhandler",
            )
            batch.set(
                img_id,
                funcinfo.addr,
                type=EntityType.DATA,
                name="__ehfuncinfo",
            )


def create_imports(db: EntityDb, image_id: ImageId, binfile: Image):
    with db.batch() as batch:
        for imp in binfile.imports:
            if imp.name:
                import_name = f"{imp.module}::{imp.name}"
            else:
                import_name = f"{imp.module}::Ordinal_{imp.ordinal}"

            batch.set(
                image_id,
                imp.addr,
                name=import_name,
                size=4,
                type=EntityType.IMPORT,
            )


def create_import_thunks(db: EntityDb, image_id: ImageId, binfile: Image):
    if not isinstance(binfile, PEImage):
        return

    with db.batch() as batch:
        for thunk in find_import_thunks(binfile):
            batch.set(
                image_id,
                thunk.addr,
                type=EntityType.IMPORT_THUNK,
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


def complete_partial_floats(db: EntityDb, image_id: ImageId, binfile: PEImage):
    """For each float entity without any data,
    read the value from the binary and set the entity name."""
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


def complete_partial_strings(db: EntityDb, image_id: ImageId, binfile: PEImage):
    """For each string/widechar entity without any data,
    read the value from the binary and set the entity name.
    If the entity has no size, read until we hit a null-terminator."""
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    with db.batch() as batch:
        for addr, string_size, is_widechar in get_strings_without_data(db, image_id):
            try:
                if is_widechar:
                    if string_size is not None:
                        # Remove 2-byte null-terminator before decoding
                        raw = binfile.read(addr, string_size)[:-2]
                    else:
                        raw = binfile.read_widechar(addr)
                        string_size = len(raw) + 2

                    decoded_string = raw.decode("utf-16-le")
                else:
                    if string_size is not None:
                        # Remove 1-byte null-terminator before decoding
                        raw = binfile.read(addr, string_size)[:-1]
                    else:
                        raw = binfile.read_string(addr)
                        string_size = len(raw) + 1

                    decoded_string = raw.decode("latin1")

                batch.set(
                    image_id,
                    addr,
                    name=entity_name_from_string(decoded_string, is_widechar),
                    size=string_size,
                )

            except (
                InvalidVirtualReadError,
                InvalidStringError,
                InvalidVirtualAddressError,
            ):
                logger.error(
                    "Failed to read %s from %s at 0x%x",
                    ("widechar" if is_widechar else "string"),
                    image_id.name.lower(),
                    addr,
                )
            except UnicodeDecodeError:
                logger.error(
                    "Could not decode %s from %s at 0x%x",
                    ("widechar" if is_widechar else "string"),
                    image_id.name.lower(),
                    addr,
                )
