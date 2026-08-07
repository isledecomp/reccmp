"""Part of the core analysis/comparison logic of `reccmp`.
These functions update the entity database based on analysis of the binary files.
"""

import logging
import re
import struct
from reccmp.formats import Image, PEImage
from reccmp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
    InvalidStringError,
)
from reccmp.types import EntityType, ImageId
from reccmp.analysis import (
    find_float_consts,
    find_import_thunks,
    find_vtordisp,
    find_eh_handlers,
    find_exception_registrations,
    is_likely_latin1,
)
from reccmp.analysis.crt_startup import (
    detect_crt_startup_arrays,
    get_crt_function_name,
)
from .db import EntityDb, ReccmpEntity, entity_name_from_string
from .queries import get_floats_without_data, get_strings_without_data

logger = logging.getLogger(__name__)


def import_sections(db: EntityDb, image_id: ImageId, binfile: Image):
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    for sect in binfile.sections:
        db.add_section(image_id, sect.virtual_range)


def match_entry(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    # The _entry symbol is referenced in the PE header so we get this match for free.
    with db.batch() as batch:
        batch.set(ImageId.RECOMP, recomp_bin.entry, type=EntityType.FUNCTION)
        batch.match(orig_bin.entry, recomp_bin.entry)


def create_crt_functions(db: EntityDb, image_id: ImageId, binfile: PEImage):
    """Create entities for all functions found to be part of the CRT array.
    This includes any functions (thunks) called indirectly."""
    crt_arrays = detect_crt_startup_arrays(db, image_id, binfile)

    with db.batch() as batch:
        for array_type, array in crt_arrays.items():
            # All entities get the same base name.
            # We could use more specific names when we have more confidence in the format.
            # e.g. "atexit_setter"
            base_name = get_crt_function_name(array_type)
            for addr in [*array.functions, *array.thunks.values()]:
                batch.set(
                    image_id,
                    addr,
                    type=EntityType.FUNCTION,
                    name=base_name,
                )


def create_analysis_strings(
    db: EntityDb, img_id: ImageId, binfile: PEImage, encoding: str = "latin1"
):
    """Search both binaries for Latin1 strings.
    We use the insert_() method so that these strings will not overwrite
    an existing entity. It's possible that some variables or pointers
    will be mistakenly identified as short strings."""
    with db.batch() as batch:
        last_range = range(0)
        for addr, string in binfile.iter_string(encoding):
            # If the address is the site of a relocation, this is a pointer, not a string.
            if addr in binfile.relocations:
                continue

            # Don't create an entity for a substring of
            # the most recently created string.
            if addr in last_range:
                continue

            if is_likely_latin1(string) and not db.intersects(img_id, addr):
                batch.set(
                    img_id,
                    addr,
                    type=EntityType.STRING,
                    name=entity_name_from_string(string),
                    size=len(string) + 1,  # including null-terminator
                )
                last_range = range(addr, addr + len(string) + 1)


def create_analysis_floats(db: EntityDb, img_id: ImageId, binfile: PEImage):
    """Add floating point constants in each binary to the database.
    We are not matching anything right now because these values are not
    deduped like strings."""
    with db.batch() as batch:
        for addr, size, float_value in find_float_consts(binfile):
            if not db.intersects(img_id, addr):
                batch.set(
                    img_id,
                    addr,
                    type=EntityType.FLOAT,
                    name=str(float_value),
                    size=size,
                )


def _seh_side_key(img_id: ImageId, field: str) -> str:
    side = "orig" if img_id == ImageId.ORIG else "recomp"
    return f"seh_{field}_{side}"


def _find_exception_owner(
    db: EntityDb, img_id: ImageId, registration_addr: int
) -> int | None:
    """Relate a registration site to a function only near its entry point."""
    owner = None
    for entity in db.all(img_id):
        addr = entity.addr(img_id)
        assert addr is not None
        if addr > registration_addr:
            break
        if entity.get("type") == EntityType.FUNCTION:
            owner = addr

    # VC5's inline form can do a few loads between entry and ``push handler``.
    if owner is None or registration_addr - owner > 32:
        return None
    return owner


def create_seh_entities(db: EntityDb, img_id: ImageId, binfile: PEImage):
    """Create SEH entities and record their structural relationships."""
    handlers = tuple(find_eh_handlers(binfile))
    registrations: dict[int, list[int]] = {}
    for registration in find_exception_registrations(binfile, handlers):
        registrations.setdefault(registration.handler_addr, []).append(
            registration.addr
        )

    with db.batch() as batch:
        for handler_addr, funcinfo in handlers:
            handler_fields = {
                _seh_side_key(img_id, "funcinfo"): funcinfo.addr,
            }
            sites = registrations.get(handler_addr, [])
            if len(sites) == 1:
                owner = _find_exception_owner(db, img_id, sites[0])
                if owner is not None:
                    handler_fields[_seh_side_key(img_id, "owner")] = owner

            # Using names derived from symbols in .cpp.s generated asm.
            batch.set(
                img_id,
                handler_addr,
                type=EntityType.LABEL,
                name="__ehhandler",
                **handler_fields,
            )
            if img_id == ImageId.ORIG:
                batch.set(
                    img_id,
                    funcinfo.addr,
                    type=EntityType.DATA,
                    name="__ehfuncinfo",
                    seh_unwinds_orig=tuple(funcinfo.unwinds),
                )
            else:
                batch.set(
                    img_id,
                    funcinfo.addr,
                    type=EntityType.DATA,
                    name="__ehfuncinfo",
                    seh_unwinds_recomp=tuple(funcinfo.unwinds),
                )

            for unwind in funcinfo.unwinds:
                if unwind.action_addr != 0:
                    batch.set(
                        img_id,
                        unwind.action_addr,
                        type=EntityType.LABEL,
                        name=f"__Unwind({unwind.target_state})",
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

    function_starts = {
        addr
        for entity in db.get_all()
        if entity.get("type") == EntityType.FUNCTION
        and entity.size(image_id) == 6
        and (addr := entity.addr(image_id)) is not None
    }

    with db.batch() as batch:
        for thunk in find_import_thunks(binfile, function_starts):
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
            if not db.exists(img_id, thunk_addr):
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
            if not db.exists(img_id, vtor.func_addr):
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


def complete_partial_strings(
    db: EntityDb, image_id: ImageId, binfile: PEImage, encoding: str = "latin1"
):
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

                    decoded_string = raw.decode(encoding)

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


def normalize_original_zero_size_data(db: EntityDb, binfile: PEImage) -> None:
    """Retype structurally proven zero-size inventory rows conservatively.

    Ghidra exports may describe interior code labels, E9 islands and named vtables as
    generic DATA. Function containment, exact opcodes and pointer-run/name agreement
    are sufficient type evidence; all other rows remain DATA for manual xref work.
    """
    functions: list[tuple[int, int]] = []
    code_ranges = [region.range for region in binfile.get_code_regions()]
    for entity in db.all(ImageId.ORIG):
        if entity.get("type") != EntityType.FUNCTION:
            continue
        addr = entity.orig_addr
        size = entity.size(ImageId.ORIG)
        if addr is not None and size is not None and size > 0:
            functions.append((addr, addr + size))
    functions.sort()

    def containing_function(addr: int) -> bool:
        for start, end in functions:
            if start >= addr:
                return False
            if addr < end:
                return True
        return False

    def in_code(addr: int) -> bool:
        return any(addr in region for region in code_ranges)

    with db.batch() as batch:
        for entity in tuple(db.unmatched(ImageId.ORIG)):
            if entity.get("type") != EntityType.DATA or entity.size(ImageId.ORIG):
                continue
            addr = entity.orig_addr
            if addr is None:
                continue
            if containing_function(addr):
                batch.set(ImageId.ORIG, addr, type=EntityType.LABEL)
                continue

            if in_code(addr):
                raw = binfile.read(addr, 5)
                if raw[0] == 0xE9:
                    target = addr + 5 + int.from_bytes(raw[1:5], "little", signed=True)
                    batch.set(
                        ImageId.ORIG,
                        addr,
                        type=EntityType.THUNK,
                        size=5,
                        skip=True,
                    )
                    batch.set_ref(ImageId.ORIG, addr, ref=target)
                continue

            name = entity.best_name() or ""
            match = re.fullmatch(r"(.+?)::(?:'vftable'|vftable)", name)
            if match is None:
                continue
            slot_count = 0
            for offset in range(0, 1024, 4):
                (target,) = struct.unpack("<I", binfile.read(addr + offset, 4))
                if not in_code(target):
                    break
                slot_count += 1
            if slot_count >= 3:
                batch.set(
                    ImageId.ORIG,
                    addr,
                    type=EntityType.VTABLE,
                    name=match.group(1),
                    size=slot_count * 4,
                    inferred_vtable=True,
                )


def _vtable_class_name(name: str | None) -> str | None:
    if not name:
        return None
    match = re.match(r"(.+?)::`vftable'", name)
    return match.group(1) if match else name


def _vtable_slot_identities(
    db: EntityDb, image_id: ImageId, binfile: PEImage, addr: int, size: int
) -> tuple[int | None, ...] | None:
    try:
        raw = binfile.read(addr, size)
    except (InvalidVirtualAddressError, InvalidVirtualReadError):
        return None
    identities: list[int | None] = []
    for (target,) in struct.iter_unpack("<I", raw):
        if target == 0:
            identities.append(None)
            continue
        canonical = db.alias_canonical_orig(image_id, target)
        if canonical is None:
            return None
        identities.append(canonical)
    return tuple(identities)


def match_inferred_vtables_by_slots(
    db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage
) -> None:
    """Pair inferred retail vtables only through exact canonical slot identities."""
    recomp_by_class: dict[str, list[ReccmpEntity]] = {}
    for entity in db.unexplained(ImageId.RECOMP):
        if entity.get("type") != EntityType.VTABLE:
            continue
        class_name = _vtable_class_name(entity.best_name())
        if class_name is not None:
            recomp_by_class.setdefault(class_name, []).append(entity)

    pairs: list[tuple[int, int]] = []
    for original in db.unexplained(ImageId.ORIG):
        if not original.get("inferred_vtable"):
            continue
        orig_addr = original.orig_addr
        orig_size = original.size(ImageId.ORIG)
        class_name = _vtable_class_name(original.best_name())
        if orig_addr is None or orig_size is None or class_name is None:
            continue
        orig_slots = _vtable_slot_identities(
            db, ImageId.ORIG, orig_bin, orig_addr, orig_size
        )
        if orig_slots is None:
            continue
        equivalent: list[int] = []
        for recomp in recomp_by_class.get(class_name, []):
            recomp_addr = recomp.recomp_addr
            recomp_size = recomp.size(ImageId.RECOMP)
            if (
                recomp_addr is None
                or recomp_size != orig_size
                or _vtable_slot_identities(
                    db, ImageId.RECOMP, recomp_bin, recomp_addr, recomp_size
                )
                != orig_slots
            ):
                continue
            equivalent.append(recomp_addr)
        if len(equivalent) == 1:
            pairs.append((orig_addr, equivalent[0]))
    db.bulk_match(pairs)


def classify_exact_vtable_aliases(
    db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage
) -> None:
    """Record exact duplicate vtable emissions against a unique canonical pair."""
    for image_id, binfile in (
        (ImageId.ORIG, orig_bin),
        (ImageId.RECOMP, recomp_bin),
    ):
        canonical: dict[tuple[str, bytes], set[int]] = {}
        for canonical_entity in db.get_matches_by_type(EntityType.VTABLE):
            addr = canonical_entity.addr(image_id)
            size = canonical_entity.size(image_id)
            name = canonical_entity.best_name()
            if addr is None or size is None or size <= 0 or name is None:
                continue
            try:
                raw = bytes(binfile.read(addr, size))
            except (InvalidVirtualAddressError, InvalidVirtualReadError):
                continue
            canonical.setdefault((name, raw), set()).add(canonical_entity.orig_addr)

        for candidate in tuple(db.unexplained(image_id)):
            if candidate.get("type") != EntityType.VTABLE:
                continue
            addr = candidate.addr(image_id)
            size = candidate.size(image_id)
            name = candidate.best_name()
            if addr is None or size is None or size <= 0 or name is None:
                continue
            try:
                raw = bytes(binfile.read(addr, size))
            except (InvalidVirtualAddressError, InvalidVirtualReadError):
                continue
            identities = canonical.get((name, raw), set())
            if len(identities) == 1:
                db.set_alias(image_id, addr, next(iter(identities)))
