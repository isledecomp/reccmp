"""Part of the core analysis/comparison logic of `reccmp`.
These functions create or update entities using the current information in the database.
"""

import logging
from reccmp.analysis.crt_startup import (
    detect_crt_startup_arrays,
    fingerprint_crt_functions,
    create_crt_matches,
    find_initializer_atexit_helpers,
)
from reccmp.cvdump.demangler import (
    get_function_arg_string,
)
from reccmp.formats import PEImage
from reccmp.types import EntityType, ImageId
from .db import EntityDb
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


def _match_crt_atexit_helpers(
    db: EntityDb,
    orig_bin: PEImage,
    recomp_bin: PEImage,
    *,
    crt_orig,
    crt_recomp,
    matches: list[tuple[int, int]],
):
    orig_initializers = {
        addr
        for array in crt_orig.values()
        if array is not None
        for addr in array.functions
        if db.exists(ImageId.ORIG, addr)
    }
    recomp_initializers = {
        addr
        for array in crt_recomp.values()
        if array is not None
        for addr in array.functions
        if db.exists(ImageId.RECOMP, addr)
    }
    orig_helpers = find_initializer_atexit_helpers(
        db, ImageId.ORIG, orig_bin, iter(orig_initializers)
    )
    recomp_helpers = find_initializer_atexit_helpers(
        db, ImageId.RECOMP, recomp_bin, iter(recomp_initializers)
    )

    helper_edges: set[tuple[int, int]] = set()
    for orig_initializer, recomp_initializer in matches:
        orig_registered = orig_helpers.get(orig_initializer, ())
        recomp_registered = recomp_helpers.get(recomp_initializer, ())
        if len(orig_registered) == 1 and len(recomp_registered) == 1:
            helper_edges.add((orig_registered[0], recomp_registered[0]))

    orig_degree: dict[int, int] = {}
    recomp_degree: dict[int, int] = {}
    for orig_helper, recomp_helper in helper_edges:
        orig_degree[orig_helper] = orig_degree.get(orig_helper, 0) + 1
        recomp_degree[recomp_helper] = recomp_degree.get(recomp_helper, 0) + 1
    with db.batch() as batch:
        for orig_helper, recomp_helper in sorted(helper_edges):
            if orig_degree[orig_helper] != 1 or recomp_degree[recomp_helper] != 1:
                continue
            orig_entity = db.get(ImageId.ORIG, orig_helper, exact=True)
            recomp_entity = db.get(ImageId.RECOMP, recomp_helper, exact=True)
            if (
                orig_entity is not None
                and recomp_entity is not None
                and not orig_entity.matched
                and not recomp_entity.matched
            ):
                batch.match(orig_helper, recomp_helper)


def match_crt_startup(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    # Startup arrays are structural evidence, not a function-boundary oracle. Only
    # enrich/match addresses that another source (inventory or PDB) already declared;
    # otherwise large retail CRT ranges would manufacture hundreds of anonymous
    # original functions and turn link-surface evidence into headline noise.
    known_orig = {
        entity.orig_addr
        for entity in db.all(ImageId.ORIG)
        if entity.orig_addr is not None
    }
    known_recomp = {
        entity.recomp_addr
        for entity in db.all(ImageId.RECOMP)
        if entity.recomp_addr is not None
    }
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

    matches = [
        (orig_addr, recomp_addr)
        for orig_addr, recomp_addr in matches
        if orig_addr in known_orig and recomp_addr in known_recomp
    ]

    with db.batch() as batch:
        for orig_addr, recomp_addr in matches:
            batch.match(orig_addr, recomp_addr)

    _match_crt_atexit_helpers(
        db,
        orig_bin,
        recomp_bin,
        crt_orig=crt_orig,
        crt_recomp=crt_recomp,
        matches=matches,
    )
