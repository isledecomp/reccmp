from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.event import (
    ReccmpEvent,
    ReccmpReportProtocol,
    reccmp_report_nop,
)


class EntityIndex:
    """One-to-many index. Maps string value to address."""

    _dict: dict[str, list[int]]

    def __init__(self) -> None:
        self._dict = {}

    def __contains__(self, key: str) -> bool:
        return key in self._dict

    def add(self, key: str, value: int):
        self._dict.setdefault(key, []).append(value)

    def count(self, key: str) -> int:
        return len(self._dict.get(key, []))

    def pop(self, key: str) -> int:
        value = self._dict[key].pop(0)
        if len(self._dict[key]) == 0:
            del self._dict[key]

        return value


def match_symbols(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    """Match all entities using the symbol attribute. We expect this value to be unique."""

    symbol_index = EntityIndex()

    for recomp_addr, symbol in db.sql.execute(
        """SELECT recomp_addr, json_extract(kvstore, '$.symbol') as symbol
        from recomp_unmatched where symbol is not null"""
    ):
        # Max symbol length in MSVC is 255 chars. See also: Warning C4786.
        symbol_index.add(symbol[:255], recomp_addr)

    with db.batch() as batch:
        for orig_addr, symbol in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.symbol') as symbol
            from orig_unmatched where symbol is not null"""
        ):
            # Same truncate to 255 chars as above.
            symbol = symbol[:255]
            if symbol in symbol_index:
                recomp_addr = symbol_index.pop(symbol)

                # If match was not unique:
                if symbol in symbol_index:
                    report(
                        ReccmpEvent.NON_UNIQUE_SYMBOL,
                        orig_addr,
                        msg=f"Matched 0x{orig_addr:x} using non-unique symbol '{symbol}'",
                    )

                batch.match(orig_addr, recomp_addr)

            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    orig_addr,
                    msg=f"Failed to match function at 0x{orig_addr:x} with symbol '{symbol}'",
                )


def match_functions(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    # addr->symbol map. Used later in error message for non-unique match.
    recomp_symbols: dict[int, str] = {}

    name_index = EntityIndex()

    # TODO: We allow a match if entity_type is null.
    # This can be removed if we can more confidently declare a symbol is a function
    # when adding from the PDB.
    for recomp_addr, name, symbol in db.sql.execute(
        """SELECT recomp_addr, json_extract(kvstore, '$.name') as name, json_extract(kvstore, '$.symbol')
        from recomp_unmatched where name is not null
        and (json_extract(kvstore, '$.type') = ? or json_extract(kvstore, '$.type') is null)""",
        (EntityType.FUNCTION,),
    ):
        # Truncate the name to 255 characters. It will not be possible to match a name
        # longer than that because MSVC truncates to this length.
        # See also: warning C4786.
        name = name[:255]
        name_index.add(name, recomp_addr)

        # Get the symbol for the error message later.
        if symbol is not None:
            recomp_symbols[recomp_addr] = symbol

    # Report if the name used in the match is not unique.
    # If the name list contained multiple addreses at the start,
    # we should report even for the last address in the list.
    non_unique_names = set()

    with db.batch() as batch:
        for orig_addr, name in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.name') as name
            from orig_unmatched where name is not null
            and json_extract(kvstore, '$.type') = ?""",
            (EntityType.FUNCTION,),
        ):
            # Repeat the truncate for our match search
            name = name[:255]

            if name in name_index:
                recomp_addr = name_index.pop(name)
                # If match was not unique
                if name in name_index:
                    non_unique_names.add(name)

                # If this name was ever matched non-uniquely
                if name in non_unique_names:
                    symbol = recomp_symbols.get(recomp_addr, "None")
                    report(
                        ReccmpEvent.AMBIGUOUS_MATCH,
                        orig_addr,
                        msg=f"Ambiguous match 0x{orig_addr:x} on name '{name}' to '{symbol}'",
                    )

                batch.match(orig_addr, recomp_addr)
            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    orig_addr,
                    msg=f"Failed to match function at 0x{orig_addr:x} with name '{name}'",
                )


def match_vtables(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    """The requirements for matching are:
    1.  Recomp entity has name attribute in this format: "Pizza::`vftable'"
        This is derived from the symbol: "??_7Pizza@@6B@"
    2.  Orig entity has name attribute with class name only. (e.g. "Pizza")
    3.  If multiple inheritance is used, the orig entity has the base_class attribute set.

    For multiple inheritance, the vtable name references the base class like this:

        - X::`vftable'{for `Y'}

    The vtable for the derived class will take one of these forms:

        - X::`vftable'{for `X'}
        - X::`vftable'

    We assume only one of the above will appear for a given class."""

    vtable_name_index = EntityIndex()

    for recomp_addr, name in db.sql.execute(
        """SELECT recomp_addr, json_extract(kvstore, '$.name') as name
        from recomp_unmatched where name is not null
        and json_extract(kvstore, '$.type') = ?""",
        (EntityType.VTABLE,),
    ):
        vtable_name_index.add(name, recomp_addr)

    with db.batch() as batch:
        for orig_addr, class_name, base_class in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.name') as name, json_extract(kvstore, '$.base_class')
            from orig_unmatched where name is not null
            and json_extract(kvstore, '$.type') = ?""",
            (EntityType.VTABLE,),
        ):
            # Most classes will not use multiple inheritance, so try the regular vtable
            # first, unless a base class is provided.
            if base_class is None or base_class == class_name:
                bare_vftable = f"{class_name}::`vftable'"

                if bare_vftable in vtable_name_index:
                    recomp_addr = vtable_name_index.pop(bare_vftable)
                    batch.match(orig_addr, recomp_addr)
                    continue

            # If we didn't find a match above, search for the multiple inheritance vtable.
            for_name = base_class if base_class is not None else class_name
            for_vftable = f"{class_name}::`vftable'{{for `{for_name}'}}"

            if for_vftable in vtable_name_index:
                recomp_addr = vtable_name_index.pop(for_vftable)
                batch.match(orig_addr, recomp_addr)
                continue

            report(
                ReccmpEvent.NO_MATCH,
                orig_addr,
                msg=f"Failed to match vtable at 0x{orig_addr:x} for class '{class_name}' (base={base_class or 'None'})",
            )


def match_static_variables(
    db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop
):
    """To match a static variable, we need the following:
    1. Orig entity function with symbol
    2. Orig entity variable with:
        - name = name of variable
        - static_var = True
        - parent_function = orig address of function
    3. Recomp entity for the static variable with symbol"""
    with db.batch() as batch:
        for (
            variable_addr,
            variable_name,
            function_name,
            function_symbol,
        ) in db.sql.execute(
            """SELECT var.orig_addr, json_extract(var.kvstore, '$.name') as name,
            json_extract(func.kvstore, '$.name'), json_extract(func.kvstore, '$.symbol')
            from orig_unmatched var left join entities func on json_extract(var.kvstore, '$.parent_function') = func.orig_addr
            where json_extract(var.kvstore, '$.static_var') = 1
            and name is not null"""
        ):
            # If we could not find the parent function, or if it has no symbol:
            if function_symbol is None:
                report(
                    ReccmpEvent.NO_MATCH,
                    variable_addr,
                    msg=f"No function for static variable '{variable_name}'",
                )
                continue

            # If the static variable has a symbol, it will contain the parent function's symbol.
            # e.g. Static variable "g_startupDelay" from function "IsleApp::Tick"
            # The function symbol is:                    "?Tick@IsleApp@@QAEXH@Z"
            # The variable symbol is: "?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA"
            for (recomp_addr,) in db.sql.execute(
                """SELECT recomp_addr FROM recomp_unmatched
                where (json_extract(kvstore, '$.type') = ? OR json_extract(kvstore, '$.type') IS NULL)
                and json_extract(kvstore, '$.symbol') LIKE '%' || ? || '%' || ? || '%'""",
                (EntityType.DATA, variable_name, function_symbol),
            ):
                batch.match(variable_addr, recomp_addr)
                break
            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    variable_addr,
                    msg=f"Failed to match static variable {variable_name} from function {function_name} annotated with 0x{variable_addr:x}",
                )


def match_variables(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    var_name_index = EntityIndex()

    # TODO: We allow a match if entity_type is null.
    # This can be removed if we can more confidently declare a symbol is a variable
    # when adding from the PDB.
    for name, recomp_addr in db.sql.execute(
        """SELECT json_extract(kvstore, '$.name') as name, recomp_addr
        from recomp_unmatched where name is not null
        and (json_extract(kvstore, '$.type') = ? or json_extract(kvstore, '$.type') is null)""",
        (EntityType.DATA,),
    ):
        var_name_index.add(name, recomp_addr)

    with db.batch() as batch:
        for orig_addr, name in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.name') as name
            from orig_unmatched where name is not null
            and json_extract(kvstore, '$.type') = ?
            and coalesce(json_extract(kvstore, '$.static_var'), 0) != 1""",
            (EntityType.DATA,),
        ):
            if name in var_name_index:
                recomp_addr = var_name_index.pop(name)
                batch.match(orig_addr, recomp_addr)
            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    orig_addr,
                    msg=f"Failed to match variable {name} at 0x{orig_addr:x}",
                )


def match_strings(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    string_index = EntityIndex()

    for recomp_addr, text in db.sql.execute(
        """SELECT recomp_addr, json_extract(kvstore, '$.name') as name
        from recomp_unmatched where name is not null
        and json_extract(kvstore,'$.type') = ?""",
        (EntityType.STRING,),
    ):
        string_index.add(text, recomp_addr)

    with db.batch() as batch:
        for orig_addr, text in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.name') as name
            from orig_unmatched where name is not null
            and json_extract(kvstore,'$.type') = ?""",
            (EntityType.STRING,),
        ):
            if text in string_index:
                recomp_addr = string_index.pop(text)
                batch.match(orig_addr, recomp_addr)
            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    orig_addr,
                    msg=f"Failed to match string {repr(text)} at 0x{orig_addr:x}",
                )
