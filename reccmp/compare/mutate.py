"""Part of the core analysis/comparison logic of `reccmp`.
These functions create or update entities using the current information in the database.
"""

import logging
from reccmp.analysis.crt_startup import (
    detect_crt_startup_arrays,
    fingerprint_crt_functions,
    create_crt_matches,
)
from reccmp.cvdump.demangler import (
    get_function_arg_string,
)
from reccmp.formats import PEImage
from reccmp.types import EntityType, ImageId
from .db import EntityDb, ReccmpEntity
from .queries import get_overloaded_functions, get_named_thunks

logger = logging.getLogger(__name__)


def set_max_size(db: EntityDb, image_id: ImageId):
    """In each section/segment of the image, for compared entities without a size value,
    calculate the distance between the entity and the solid entity that follows.
    Same calculation as db.get_max_size()."""
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    # Any entity that takes up space can be used to measure against.
    solid_types = EntityType.solid_types()

    # We don't want to measure the size of const data entities like strings.
    # They already have an intrinsic size.
    measured_types = EntityType.variable_size_types()

    with db.batch() as batch:
        for range_ in db.sections(image_id):
            last_addr = None

            for ent in db.all_in_range(image_id, range_):
                this_type = ent.get("type")
                if this_type not in solid_types:
                    # Also excludes null type.
                    continue

                this_addr = ent.addr(image_id)
                assert this_addr is not None

                if last_addr is not None:
                    batch.set(image_id, last_addr, max_size=this_addr - last_addr)
                    last_addr = None

                # Only measure entities with no set size
                if last_addr is None and ent.size(image_id) is None:
                    if this_type in measured_types:
                        # Measure this entity next.
                        last_addr = this_addr

            # Measured against the end of the section/image.
            if last_addr is not None:
                batch.set(image_id, last_addr, max_size=range_.stop - last_addr)


def match_span_anchored_functions(db: EntityDb):
    """Match annotated functions that no symbol can reach by anchoring them
    inside a preserved span between matched neighbors.

    A static function (e.g. a CRT-internal helper like _write_multi_char) is
    invisible in the PDB, so an annotation for it can never be matched by
    name. Its address is still fully determined by its object's section
    contribution: it keeps its offset relative to the surrounding, matchable
    functions as long as that span is reproduced. For each unmatched annotated
    FUNCTION entity that lies between two matched functions whose span has the
    same length in both images, match it at the same offset in the recompiled
    image. The regular function comparison still scores the new match, so a
    wrong anchor shows up as a mismatch instead of passing silently.

    A candidate is skipped when any entity already exists at the anchored
    recomp address: a known entity there means the symbol table disagrees
    with the anchoring, and the annotation should then only match by name."""

    anchor: ReccmpEntity | None = None
    pending: list[ReccmpEntity] = []

    with db.batch() as batch:
        for ent in db.all(ImageId.ORIG):
            if ent.entity_type != EntityType.FUNCTION:
                continue

            if not ent.matched:
                if anchor is not None and not ent.get("stub", False):
                    pending.append(ent)
                continue

            # A matched function closes the current span.
            if pending:
                assert anchor is not None
                anchor_orig = anchor.addr(ImageId.ORIG)
                anchor_recomp = anchor.addr(ImageId.RECOMP)
                close_orig = ent.addr(ImageId.ORIG)
                close_recomp = ent.addr(ImageId.RECOMP)
                assert anchor_orig is not None and anchor_recomp is not None
                assert close_orig is not None and close_recomp is not None

                if close_orig - anchor_orig == close_recomp - anchor_recomp:
                    # Each static extends at most to the next function in the
                    # span (finally, the closing anchor).
                    bounds = [s.addr(ImageId.ORIG) for s in pending[1:]]
                    bounds.append(close_orig)

                    for static, bound in zip(pending, bounds):
                        static_orig = static.addr(ImageId.ORIG)
                        assert static_orig is not None and bound is not None
                        candidate = anchor_recomp + (static_orig - anchor_orig)
                        if db.get(ImageId.RECOMP, candidate) is not None:
                            continue

                        batch.match(static_orig, candidate)
                        # Without any size the match cannot be compared (and
                        # would silently disappear from the report). The span
                        # is preserved, so the orig-side extent bound applies
                        # to the recomp side as well.
                        if static.size(ImageId.RECOMP) is None:
                            batch.set(
                                ImageId.RECOMP, candidate, size=bound - static_orig
                            )

            anchor = ent
            pending.clear()


def name_thunks(db: EntityDb):
    """Add the 'Thunk of' prefix or 'vtordisp{x,y}' suffix to thunk or vtordisp entities.
    The current behavior is to use the computed_name (disambiguated) for an entity as the
    entity's "name" attribute."""

    with db.batch() as batch:
        for img, addr, name in get_named_thunks(db):
            batch.set(img, addr, name=name)


def unique_names_for_overloaded_functions(db: EntityDb):
    """Our asm sanitize will use the "friendly" name of a function.
    Overloaded functions will all have the same name. This function detects those
    cases and gives each one a unique name in the db."""
    with db.batch() as batch:
        for func in get_overloaded_functions(db):
            # Just number it to start, in case we don't have a symbol.
            new_name = f"{func.name}({func.nth})"

            if func.symbol is not None:
                dm_args = get_function_arg_string(func.symbol)
                if dm_args is not None:
                    new_name = f"{func.name}{dm_args}"

            if func.orig_addr is not None:
                batch.set(ImageId.ORIG, func.orig_addr, computed_name=new_name)
            elif func.recomp_addr is not None:
                batch.set(ImageId.RECOMP, func.recomp_addr, computed_name=new_name)


def match_crt_startup(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    """Match CRT function entities established in create_crt_functions().
    For best performance, call after set_max_size() has provided a limit for
    CRT function size. Otherwise, the fingerprint sampler will read more
    bytes than necessary for each function."""
    crt_orig = detect_crt_startup_arrays(db, ImageId.ORIG, orig_bin)
    crt_recomp = detect_crt_startup_arrays(db, ImageId.RECOMP, recomp_bin)

    matches = []

    for array_type, orig_array in crt_orig.items():
        recomp_array = crt_recomp.get(array_type)
        if recomp_array is None:
            continue

        if orig_array.functions and recomp_array.functions:
            fingerprint_crt_functions(db, ImageId.ORIG, orig_bin, orig_array)
            fingerprint_crt_functions(db, ImageId.RECOMP, recomp_bin, recomp_array)
            matches.extend(create_crt_matches(orig_array, recomp_array))

    with db.batch() as batch:
        for orig_addr, recomp_addr in matches:
            batch.match(orig_addr, recomp_addr)
