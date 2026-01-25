from reccmp.decomp.types import EntityType
from reccmp.decomp.compare.db import EntityDb
from reccmp.decomp.compare.lines import LinesDb
from reccmp.decomp.compare.event import (
    ReccmpEvent,
    ReccmpReportProtocol,
    reccmp_report_nop,
)
from reccmp.decomp.compare.queries import get_referencing_entity_matches


class EntityIndex:
    """One-to-many index. Maps string value to address."""

    _dict: dict[str, list[int]]

    def __init__(self) -> None:
        self._dict = {}

    def __contains__(self, key: str) -> bool:
        return key in self._dict

    def add(self, key: str, value: int):
        self._dict.setdefault(key, []).append(value)

    def get(self, key: str) -> list[int]:
        return self._dict.get(key, [])

    def count(self, key: str) -> int:
        return len(self._dict.get(key, []))

    def pop(self, key: str) -> int:
        value = self._dict[key].pop(0)
        if len(self._dict[key]) == 0:
            del self._dict[key]

        return value


def match_symbols(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
    *,
    truncate: bool = False,
):
    """Match all entities with the 'symbol' attribute set. We expect this value to be unique."""

    symbol_index = EntityIndex()

    for recomp_addr, symbol in db.sql.execute(
        """SELECT recomp_addr, json_extract(kvstore, '$.symbol') as symbol
        from recomp_unmatched where symbol is not null"""
    ):
        # Truncate symbol to 255 chars for older MSVC. See also: Warning C4786.
        if truncate:
            symbol = symbol[:255]

        symbol_index.add(symbol, recomp_addr)

    with db.batch() as batch:
        for orig_addr, symbol in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.symbol') as symbol
            from orig_unmatched where symbol is not null"""
        ):
            # Repeat the truncate for our match search
            if truncate:
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
                    msg=f"Failed to match at 0x{orig_addr:x} with symbol '{symbol}'",
                )


def match_functions(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
    *,
    truncate: bool = False,
):
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
        # Truncate function name to 255 chars for older MSVC. See also: Warning C4786.
        if truncate:
            name = name[:255]

        name_index.add(name, recomp_addr)

        # Get the symbol for the error message later.
        if symbol is not None:
            recomp_symbols[recomp_addr] = symbol

    # Report if the name used in the match is not unique.
    # If the name list contained multiple addresses at the start,
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
            if truncate:
                name = name[:255]

            if name in name_index:
                recomp_addr = name_index.pop(name)
                # If match was not unique
                if name in name_index:
                    non_unique_names.add(name)

                # If this name was ever matched non-uniquely
                if name in non_unique_names:
                    matched_symbol = recomp_symbols.get(recomp_addr, "None")
                    other_symbols = [
                        recomp_symbols.get(recomp_addr, "None")
                        for recomp_addr in name_index.get(name)
                    ]
                    report(
                        ReccmpEvent.AMBIGUOUS_MATCH,
                        orig_addr,
                        msg=f"Ambiguous match 0x{orig_addr:x} on name '{name}' to\n"
                        + f"'{matched_symbol}'\n"
                        + "Other candidates:\n"
                        + ",\n".join(f"'{candidate}'" for candidate in other_symbols),
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
    3. Recomp entity for the static variable with symbol

    Requirement #1 is most likely to be met by matching the entity with recomp data.
    Therefore, this function should be called after match_symbols or match_functions."""
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
        and json_extract(kvstore,'$.type') IN (?, ?)""",
        (EntityType.STRING, EntityType.WIDECHAR),
    ):
        string_index.add(text, recomp_addr)

    with db.batch() as batch:
        for orig_addr, text, verified in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.name') as name,
            coalesce(json_extract(kvstore,'$.verified'), 0)
            from orig_unmatched where name is not null
            and json_extract(kvstore,'$.type') IN (?, ?)""",
            (EntityType.STRING, EntityType.WIDECHAR),
        ):
            if text in string_index:
                recomp_addr = string_index.pop(text)
                batch.match(orig_addr, recomp_addr)
            elif verified:
                report(
                    ReccmpEvent.NO_MATCH,
                    orig_addr,
                    msg=f"Failed to match string {text} at 0x{orig_addr:x}",
                )


def match_lines(
    db: EntityDb,
    lines: LinesDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    """
    This function requires access to `cv` and `recomp_bin` because most lines will not have an annotation.
    It would therefore be quite inefficient to load all recomp lines into the `entities` table
    and only match a tiny fraction of them to symbols.
    """

    with db.batch() as batch:
        for orig_addr, filename, line in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.filename') as filename, json_extract(kvstore, '$.line') as line
            FROM orig_unmatched
            WHERE json_extract(kvstore,'$.type') = ?""",
            (EntityType.LINE,),
        ):
            #
            # We only match the line directly below the annotation since not all lines of code result in a debug line, especially if optimizations are turned on.
            # However, this does cause false positives in cases like
            # ```
            # // LINE: TARGET 0x1234
            # // OTHER_ANNOTATION: ...
            # actual_code();
            # ```
            # or
            # ```
            # // LINE: TARGET 0x1234
            #
            # actual_code();
            # ```
            # but it is significantly more effort to detect these false positives.
            #

            # We match `line + 1` since `line` is the comment itself
            for recomp_addr in lines.search_line(filename, line + 1):
                batch.set_recomp_addr(orig_addr, recomp_addr)
                break
            else:
                # No results
                report(
                    ReccmpEvent.NO_MATCH,
                    orig_addr,
                    f"Found no matching debug symbol for {filename}:{line}",
                )


def match_ref(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    """Matches child entities that refer to the same parent entity.
    Repeats until there are no new matches."""
    new_matches = False

    for _ in range(10):
        new_matches = False
        with db.batch() as batch:
            for orig_addr, recomp_addr in get_referencing_entity_matches(db):
                new_matches = True
                batch.match(orig_addr, recomp_addr)

            if not new_matches:
                break

    # If we did not break out of the loop:
    if new_matches:
        report(
            ReccmpEvent.GENERAL_WARNING,
            -1,
            "Reached maximum iteration depth while matching referencing entities.",
        )


def match_imports(db: EntityDb):
    orig_query = """
        SELECT orig_addr, json_extract(kvstore, '$.name') name
        FROM orig_unmatched
        WHERE json_extract(kvstore, '$.type') = ?
        AND name IS NOT NULL
    """

    recomp_query = """
        SELECT recomp_addr, json_extract(kvstore, '$.name') name
        FROM recomp_unmatched
        WHERE json_extract(kvstore, '$.type') = ?
        AND name IS NOT NULL
    """

    # n.b. Case insensitive match here to preserve previous behavior.
    # The final entity will use the name from the recomp side.
    orig_imports = {
        name.upper(): addr
        for addr, name in db.sql.execute(orig_query, (EntityType.IMPORT,))
    }

    with db.batch() as batch:
        for recomp_addr, name in db.sql.execute(recomp_query, (EntityType.IMPORT,)):
            orig_addr = orig_imports.get(name.upper())
            if orig_addr is not None:
                batch.match(orig_addr, recomp_addr)
