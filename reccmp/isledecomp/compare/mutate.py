"""Part of the core analysis/comparison logic of `reccmp`.
These functions create or update entities using the current information in the database.
"""

import logging
from reccmp.isledecomp.cvdump.demangler import (
    get_function_arg_string,
)
from reccmp.isledecomp.cvdump import CvdumpTypesParser
from reccmp.isledecomp.types import EntityType
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

    # Helper function
    def _add_match_in_array(
        name: str, type_id: str, orig_addr: int, recomp_addr: int, max_orig: int
    ):
        # pylint: disable=unused-argument
        # TODO: Previously used scalar_type_pointer(type_id) to set whether this is a pointer
        if recomp_addr in seen_recomp:
            return

        seen_recomp.add(recomp_addr)
        batch.set_recomp(recomp_addr, name=name)
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
                _add_match_in_array(
                    f"{match.name}{array_element.name}",
                    array_element_type.key,
                    orig_element_base_addr,
                    recomp_element_base_addr,
                    upper_bound,
                )

            else:
                # Else: multidimensional array or array of structs
                for member in array_element_type.members:
                    _add_match_in_array(
                        f"{match.name}{array_element.name}.{member.name}",
                        array_element_type.key,
                        orig_element_base_addr + member.offset,
                        recomp_element_base_addr + member.offset,
                        upper_bound,
                    )

    batch.commit()


def name_thunks(db: EntityDb):
    with db.batch() as batch:
        for thunk in get_named_thunks(db):
            if thunk.orig_addr is not None:
                batch.set_orig(thunk.orig_addr, name=f"Thunk of '{thunk.name}'")

            elif thunk.recomp_addr is not None:
                batch.set_recomp(thunk.recomp_addr, name=f"Thunk of '{thunk.name}'")


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
