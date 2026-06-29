"""Part of the core analysis/comparison logic of `reccmp`.
These functions create or update entities using the current information in the database.
"""

import logging
from reccmp.analysis.crt_startup import (
    detect_crt_startup_arrays,
    create_crt_matches,
    get_crt_function_name,
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


def match_crt_startup(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    crt_orig = tuple(detect_crt_startup_arrays(db, ImageId.ORIG, orig_bin))
    crt_recomp = tuple(detect_crt_startup_arrays(db, ImageId.RECOMP, recomp_bin))

    matches = []

    for (orig_type, orig_array), (recomp_type, recomp_array) in zip(
        crt_orig, crt_recomp
    ):
        # Safety
        assert orig_type == recomp_type
        if orig_array and recomp_array:
            matches.extend(create_crt_matches(orig_array, recomp_array))

    with db.batch() as batch:
        for image_id, crt_arrays in (
            (ImageId.ORIG, crt_orig),
            (ImageId.RECOMP, crt_recomp),
        ):
            for array_type, array in crt_arrays:
                if array is None:
                    continue

                name = get_crt_function_name(array_type)

                for addr in array.functions.keys():
                    batch.set(
                        image_id,
                        addr,
                        type=EntityType.FUNCTION,
                        name=name,
                    )

                    if addr in array.thunks:
                        thunk_addr = array.thunks[addr]
                        batch.set(
                            image_id,
                            thunk_addr,
                            type=EntityType.FUNCTION,
                            name=name,
                        )

        for orig_addr, recomp_addr in matches:
            batch.match(orig_addr, recomp_addr)
