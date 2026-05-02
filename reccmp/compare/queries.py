from typing import Iterator, NamedTuple
from reccmp.types import EntityType, ImageId
from .db import EntityDb, ReccmpEntity


class OverloadedFunctionEntity(NamedTuple):
    orig_addr: int | None
    recomp_addr: int | None
    name: str
    symbol: str | None
    # The number for this repeated name, starting at 1, ordered by orig_addr (nulls last), then recomp_addr.
    nth: int


def get_overloaded_functions(db: EntityDb) -> Iterator[OverloadedFunctionEntity]:
    """Find each function that has a non-unique name shared with other function entities.
    Uses a SQL window function to get the number for the repeated name so the caller
    doesn't need to keep track. We assume that a better name can be derived from
    the entity's symbol so we return that too."""
    name_cache: dict[str, list[ReccmpEntity]] = {}

    for ent in db.get_all():
        if ent.get("type") != EntityType.FUNCTION:
            continue

        name = ent.get("name")
        if name is None:
            continue

        name_cache.setdefault(name, []).append(ent)

    for _, names in name_cache.items():
        if len(names) < 2:
            continue

        for nth, ent in enumerate(names, start=1):
            assert isinstance(ent.orig_addr, int) or isinstance(ent.recomp_addr, int)
            name = ent.get("name")
            symbol = ent.get("symbol")
            assert isinstance(name, str)
            assert isinstance(symbol, str) or symbol is None
            yield OverloadedFunctionEntity(
                ent.orig_addr, ent.recomp_addr, name, symbol, nth
            )


class ThunkWithName(NamedTuple):
    """Entity address(es) and the name (computed or base name)
    of the referenced (thunked) entity."""

    img_id: ImageId
    addr: int
    name: str


def get_named_thunks(db: EntityDb) -> Iterator[ThunkWithName]:
    """Return a modified name to set for each thunk and vtordisp entity.
    The name is copied from the parent function entity.
    Must run db.populate_names_table() and db,propagate_thunk_names() first."""

    # Names, propagated as we complete the graph.
    names: dict[tuple[ImageId, int], str] = {}

    # Reverse nodes from parent function into each thunk
    graph: dict[tuple[ImageId, int], list[int]] = {}

    # Cache so we only fetch once.
    refs: dict[tuple[ImageId, int], tuple[EntityType, tuple[int, int]]] = {}

    for ent in db.get_all():
        type_ = ent.get("type")
        if type_ not in (
            EntityType.THUNK,
            EntityType.VTORDISP,
            EntityType.IMPORT_THUNK,
        ):
            continue

        disp = ent.get("displacement")
        if disp is None:
            continue

        # TODO: yuck
        for ref_img, ref_key in [
            (ImageId.ORIG, "ref_orig"),
            (ImageId.RECOMP, "ref_recomp"),
        ]:
            ref_addr = ent.get(ref_key)
            if not isinstance(ref_addr, int):
                continue

            this_addr = ent.addr(ref_img)
            assert this_addr is not None

            refs[(ref_img, this_addr)] = (type_, disp)

            # Set for both address spaces. We will dedupe later.
            graph.setdefault((ref_img, ref_addr), []).append(this_addr)

            parent = db.get(ref_img, ref_addr)
            if parent is None:
                continue

            # Only functions can be the source of a name chain
            if parent.get("type") not in (EntityType.FUNCTION, EntityType.IMPORT):
                continue

            name = parent.best_name()
            if name is not None:
                names[(ref_img, ref_addr)] = name

    # propagate names step.
    # TODO: dumb. should be exhaustive with known stop.
    for _ in range(10):
        new_names = {}
        for (img, addr), name in names.items():
            if (img, addr) in graph:
                for thunk_addr in graph[(img, addr)]:
                    new_names[(img, thunk_addr)] = name

        names.update(new_names)

    # TODO: dedupe here.
    for (img, addr), (type_, (disp0, disp1)) in refs.items():
        name = names.get((img, addr))
        if not name:
            continue

        if type_ == EntityType.THUNK:
            yield ThunkWithName(img, addr, f"Thunk of '{name}'")
        elif type_ == EntityType.VTORDISP:
            yield ThunkWithName(img, addr, f"{name}`vtordisp{{{disp0}, {disp1}}}'")
        else:
            # Copy the name only
            yield ThunkWithName(img, addr, name)


def get_floats_without_data(
    db: EntityDb, image_id: ImageId
) -> Iterator[tuple[int, bool]]:
    """For each partially-created float entity (without data) in the given address space,
    return the address and whether it has double precision."""
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    for ent in db.all(image_id):
        if ent.get("type") != EntityType.FLOAT:
            continue

        # TODO: #27. We are using the name field to store the data for now,
        # but we should put this data in its own table.
        if ent.get("name") is not None:
            continue

        size = ent.any_size(image_id)
        if size not in (4, 8):
            continue

        addr = ent.addr(image_id)
        if isinstance(addr, int):
            yield (addr, size == 8)


def get_strings_without_data(
    db: EntityDb, image_id: ImageId
) -> Iterator[tuple[int, int | None, bool]]:
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    for ent in db.all(image_id):
        type_ = ent.get("type")
        if type_ not in (EntityType.STRING, EntityType.WIDECHAR):
            continue

        # TODO: #27. We are using the name field to store the data for now,
        # but we should put this data in its own table.
        if ent.get("name") is not None:
            continue

        size = ent.size(image_id)
        addr = ent.addr(image_id)

        if isinstance(addr, int):
            yield (addr, size, type_ == EntityType.WIDECHAR)


def get_referencing_entity_matches(db: EntityDb) -> Iterator[tuple[int, int]]:
    """Return new matches for child entities that refer to the same parent entity.
    These can be import thunks, incremental build thunks, or vtordisps.
    To match, the child entities must have the same displacement values (or none).
    If we cannot match uniquely, match by child address order in each address space.
    """
    orig_refs_index: dict[tuple[int, tuple], list[int]] = {}

    for ent in db.unmatched(ImageId.ORIG):
        ref = ent.get("ref_orig")
        disp = ent.get("displacement")

        # Only valid refs
        if not ref or not disp:
            continue

        # Only matched parents
        parent = db.get(ImageId.ORIG, ref)
        if not parent or not parent.matched:
            continue

        assert isinstance(ent.orig_addr, int)
        assert isinstance(ref, int)
        assert isinstance(disp, tuple)
        # Using ref orig addr as the match key.
        orig_refs_index.setdefault((ref, disp), []).append(ent.orig_addr)

    for ent in db.unmatched(ImageId.RECOMP):
        ref = ent.get("ref_recomp")
        disp = ent.get("displacement")

        # Only valid refs
        if not ref or not disp:
            continue

        # Only matched parents
        parent = db.get(ImageId.RECOMP, ref)
        if not parent or not parent.matched:
            continue

        assert parent.orig_addr is not None
        assert isinstance(ref, int)
        assert isinstance(disp, tuple)
        key = (parent.orig_addr, disp)

        if key in orig_refs_index:
            orig_addr = orig_refs_index[key].pop(0)
            if not orig_refs_index[key]:
                del orig_refs_index[key]

            assert isinstance(ent.recomp_addr, int)
            yield (orig_addr, ent.recomp_addr)
