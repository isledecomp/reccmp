"""Part of the core analysis/comparison logic of `reccmp`.
These functions create or update entities using the current information in the database.
"""

import logging
from functools import cache
from reccmp.decomp.cvdump.demangler import (
    get_function_arg_string,
)
from reccmp.decomp.cvdump import CvdumpTypesParser
from reccmp.decomp.types import EntityType
from .db import EntityDb
from .queries import get_overloaded_functions, get_named_thunks


logger = logging.getLogger(__name__)


def match_array_elements(db: EntityDb, types: CvdumpTypesParser):
    """
    For each matched variable, check whether it is an array.
    If yes, adds a match for all its elements. If it is an array of structs, all fields in that struct are also matched.
    Note that there is no recursion, so an array of arrays would not be handled entirely.
    This step is necessary e.g. for `0x100f0a20` (LegoRacers.cpp).
    """
    seen_recomp = set()
    batch = db.batch()

    @cache
    def get_type_size(type_key: str) -> int:
        type_ = types.get(type_key)
        assert type_.size is not None
        return type_.size

    # Helper function
    def _add_match_in_array(
        name: str,
        size: int,
        orig_addr: int,
        recomp_addr: int,
        max_orig: int,
        is_main_variable: bool,
    ):
        if recomp_addr in seen_recomp:
            return

        seen_recomp.add(recomp_addr)

        if is_main_variable:
            # Don't replace the type or size of the main variable entity.
            batch.set_recomp(recomp_addr, name=name)
        else:
            batch.set_recomp(recomp_addr, name=name, size=size, type=EntityType.OFFSET)

        if orig_addr < max_orig:
            batch.match(orig_addr, recomp_addr)

    for match in db.get_matches_by_type(EntityType.DATA):
        # TODO: The type information we need is in multiple places. (See #106)
        type_key = match.get("data_type")
        if type_key is None:
            continue

        if not type_key.startswith("0x"):
            # scalar type, so clearly not an array
            continue

        type_dict = types.keys.get(type_key.lower())
        if type_dict is None:
            continue

        if type_dict.get("type") != "LF_ARRAY":
            continue

        array_type_key = type_dict.get("array_type")
        if array_type_key is None:
            continue

        data_type = types.get(type_key.lower())

        # Check whether another orig variable appears before the end of the array in recomp.
        # If this happens we can still add all the recomp offsets, but do not attach the orig address
        # where it would extend into the next variable.
        upper_bound = match.orig_addr + match.size
        if (
            next_orig := db.get_next_orig_addr(match.orig_addr)
        ) is not None and next_orig < upper_bound:
            logger.warning(
                "Array variable %s at 0x%x is larger in recomp",
                match.name,
                match.orig_addr,
            )
            upper_bound = next_orig

        array_element_type = types.get(array_type_key)

        assert data_type.members is not None

        for array_element in data_type.members:
            orig_element_base_addr = match.orig_addr + array_element.offset
            recomp_element_base_addr = match.recomp_addr + array_element.offset
            if array_element_type.members is None:
                # If array of scalars
                assert array_element_type.size is not None
                _add_match_in_array(
                    f"{match.name}{array_element.name}",
                    array_element_type.size,
                    orig_element_base_addr,
                    recomp_element_base_addr,
                    upper_bound,
                    array_element.offset == 0,
                )

            else:
                # Else: multidimensional array or array of structs
                for member in array_element_type.members:
                    _add_match_in_array(
                        f"{match.name}{array_element.name}.{member.name}",
                        get_type_size(member.type),
                        orig_element_base_addr + member.offset,
                        recomp_element_base_addr + member.offset,
                        upper_bound,
                        array_element.offset + member.offset == 0,
                    )

    batch.commit()


def propagate_names(db: EntityDb):
    """Copy the name and computed_name attributes from a parent entity
    down to any thunks or vtordisp entities that refer back to it."""
    db.populate_names_table()

    # If there are chains of thunks (e.g. thunk -> vtordisp -> thunk -> function )
    # we need to repeat the name propagation step to cover all entities.
    # Stop if no names were added on this pass.
    for _ in range(10):
        if not db.propagate_thunk_names():
            break


def name_thunks(db: EntityDb):
    """Add the 'Thunk of' prefix or 'vtordisp{x,y}' suffix to thunk or vtordisp entities.
    Should be run after propagate_names() or this will have no effect.
    (i.e. It needs data in the NAMES table.)
    The current behavior is to use the computed_name (disambiguated) for an entity as the
    entity's "name" attribute."""
    propagate_names(db)

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
                batch.set_orig(func.orig_addr, computed_name=new_name)
            elif func.recomp_addr is not None:
                batch.set_recomp(func.recomp_addr, computed_name=new_name)
