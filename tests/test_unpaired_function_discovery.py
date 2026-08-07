# pylint: disable=protected-access
from unittest.mock import Mock

from reccmp.compare.db import EntityDb
from reccmp.compare.functions import FunctionComparator
from reccmp.types import EntityType, ImageId


def make_graph_comparator(db: EntityDb, fingerprints, edges):
    comparator = object.__new__(FunctionComparator)
    comparator.db = db
    comparator.equivalence_groups = {}
    comparator._alias_fingerprint = Mock(  # type: ignore[method-assign]
        side_effect=lambda image, addr, size: fingerprints.get((image, addr))
    )
    comparator.raw_pair_alias_equivalent = Mock(  # type: ignore[method-assign]
        side_effect=lambda orig, recomp, size: (orig, recomp) in edges
    )
    return comparator


def add_functions(db, image, *addrs):
    with db.batch() as batch:
        for addr in addrs:
            batch.set(image, addr, type=EntityType.FUNCTION, size=5)


def test_discovery_reaches_fixed_point_after_operand_pair():
    db = EntityDb()
    add_functions(db, ImageId.ORIG, 0x100, 0x200)
    add_functions(db, ImageId.RECOMP, 0x300, 0x400)

    leaf = (("ret", ""),)
    caller = (("call", "<ADDR>"),)
    fingerprints = {
        (ImageId.ORIG, 0x200): leaf,
        (ImageId.RECOMP, 0x400): leaf,
    }
    comparator = make_graph_comparator(
        db, fingerprints, {(0x100, 0x300), (0x200, 0x400)}
    )

    # Simulate sanitizer identity becoming available after the leaf pair.
    def fingerprint(image, addr, _size):
        if addr in (0x100, 0x300):
            if db.is_match(0x200, 0x400):
                return caller
            return None
        return fingerprints.get((image, addr))

    comparator._alias_fingerprint = Mock(  # type: ignore[method-assign]
        side_effect=fingerprint
    )
    assert comparator.discover_unpaired_function_bodies() == [
        (0x200, 0x400),
        (0x100, 0x300),
    ]


def test_discovery_preserves_ambiguous_many_to_one_graph():
    db = EntityDb()
    add_functions(db, ImageId.ORIG, 0x100, 0x200)
    add_functions(db, ImageId.RECOMP, 0x300)
    shape = (("ret", ""),)
    fingerprints = {
        (ImageId.ORIG, 0x100): shape,
        (ImageId.ORIG, 0x200): shape,
        (ImageId.RECOMP, 0x300): shape,
    }
    comparator = make_graph_comparator(
        db, fingerprints, {(0x100, 0x300), (0x200, 0x300)}
    )

    assert not comparator.discover_unpaired_function_bodies()
    assert not list(db.get_matches())
    assert len(list(db.unexplained(ImageId.ORIG))) == 2


def test_discovery_uses_declared_canonical_for_folded_many_to_one_graph():
    db = EntityDb()
    add_functions(db, ImageId.ORIG, 0x100, 0x110)
    add_functions(db, ImageId.RECOMP, 0x200)
    shape = (("ret", ""),)
    fingerprints = {
        (ImageId.ORIG, 0x100): shape,
        (ImageId.ORIG, 0x110): shape,
        (ImageId.RECOMP, 0x200): shape,
    }
    comparator = make_graph_comparator(
        db, fingerprints, {(0x100, 0x200), (0x110, 0x200)}
    )
    comparator.equivalence_groups = {0x110: 0x100}

    assert comparator.discover_unpaired_function_bodies() == [(0x100, 0x200)]
    aliases = list(db.get_aliases(ImageId.ORIG))
    assert [(alias.orig_addr, canonical.orig_addr) for alias, canonical in aliases] == [
        (0x110, 0x100)
    ]


def test_aliases_are_symmetric_and_do_not_create_fake_pairs():
    db = EntityDb()
    add_functions(db, ImageId.ORIG, 0x100, 0x110)
    add_functions(db, ImageId.RECOMP, 0x200, 0x210)
    db.bulk_match([(0x100, 0x200)])
    shape = (("ret", ""),)
    fingerprints = {
        (ImageId.ORIG, 0x100): shape,
        (ImageId.ORIG, 0x110): shape,
        (ImageId.RECOMP, 0x200): shape,
        (ImageId.RECOMP, 0x210): shape,
    }
    # Cross-unmatched equivalence is deliberately absent: each duplicate is
    # independently proven against the existing canonical body.
    comparator = make_graph_comparator(
        db, fingerprints, {(0x110, 0x200), (0x100, 0x210)}
    )

    assert not comparator.discover_unpaired_function_bodies()
    assert [(e.orig_addr, c.orig_addr) for e, c in db.get_aliases(ImageId.ORIG)] == [
        (0x110, 0x100)
    ]
    assert [
        (e.recomp_addr, c.orig_addr) for e, c in db.get_aliases(ImageId.RECOMP)
    ] == [(0x210, 0x100)]
    assert len(list(db.get_matches())) == 1
    assert len(list(db.unmatched(ImageId.ORIG))) == 1
    assert not list(db.unexplained(ImageId.ORIG))
    assert not list(db.unexplained(ImageId.RECOMP))


def test_alias_identity_unlocks_a_real_caller_pair():
    db = EntityDb()
    add_functions(db, ImageId.ORIG, 0x100, 0x110, 0x120)
    add_functions(db, ImageId.RECOMP, 0x200, 0x220)
    db.bulk_match([(0x100, 0x200)])
    leaf = (("ret", ""),)
    caller = (("call", "<ADDR>"),)
    fingerprints = {
        (ImageId.ORIG, 0x100): leaf,
        (ImageId.ORIG, 0x110): leaf,
        (ImageId.ORIG, 0x120): caller,
        (ImageId.RECOMP, 0x200): leaf,
        (ImageId.RECOMP, 0x220): caller,
    }
    comparator = make_graph_comparator(db, fingerprints, {(0x110, 0x200)})

    def equivalent(orig, recomp, _size):
        if (orig, recomp) == (0x110, 0x200):
            return True
        if (orig, recomp) == (0x120, 0x220):
            return db.alias_canonical_orig(ImageId.ORIG, 0x110) == 0x100
        return False

    comparator.raw_pair_alias_equivalent = Mock(  # type: ignore[method-assign]
        side_effect=equivalent
    )
    assert comparator.discover_unpaired_function_bodies() == [(0x120, 0x220)]
    assert db.alias_canonical_orig(ImageId.ORIG, 0x110) == 0x100


def test_alias_with_two_canonical_identities_stays_unexplained():
    db = EntityDb()
    add_functions(db, ImageId.ORIG, 0x100, 0x110, 0x120)
    add_functions(db, ImageId.RECOMP, 0x200, 0x210)
    db.bulk_match([(0x100, 0x200), (0x110, 0x210)])
    shape = (("ret", ""),)
    fingerprints = {
        (ImageId.ORIG, 0x100): shape,
        (ImageId.ORIG, 0x110): shape,
        (ImageId.ORIG, 0x120): shape,
        (ImageId.RECOMP, 0x200): shape,
        (ImageId.RECOMP, 0x210): shape,
    }
    comparator = make_graph_comparator(
        db, fingerprints, {(0x120, 0x200), (0x120, 0x210)}
    )

    assert not comparator.discover_unpaired_function_bodies()
    assert not list(db.get_aliases(ImageId.ORIG))
    assert [entity.orig_addr for entity in db.unexplained(ImageId.ORIG)] == [0x120]


def test_fingerprint_rejects_one_sided_relocation():
    db = EntityDb()
    code = b"\xb8\x00\x10\x00\x00\xc3"  # mov eax, 0x1000; ret

    def image(relocated):
        result = Mock(spec=[])
        result.read = Mock(return_value=code)
        result.imagebase = 0
        result.is_relocated_addr = Mock(return_value=relocated)
        return result

    comparator = object.__new__(FunctionComparator)
    comparator.db = db
    comparator.orig_bin = image(True)
    comparator.recomp_bin = image(False)
    comparator.is_32bit = True

    assert comparator._alias_fingerprint(
        ImageId.ORIG, 0x100, len(code)
    ) != comparator._alias_fingerprint(ImageId.RECOMP, 0x200, len(code))


def test_paired_callsite_discovery_selects_only_mutually_unique_edges():
    db = EntityDb()
    add_functions(db, ImageId.ORIG, 0x100, 0x110, 0x120)
    add_functions(db, ImageId.RECOMP, 0x200, 0x210)
    comparator = object.__new__(FunctionComparator)
    comparator.db = db
    comparator._paired_caller_identity_edges = Mock(  # type: ignore[method-assign]
        side_effect=[{(0x100, 0x200), (0x110, 0x210), (0x120, 0x210)}, set()]
    )

    assert comparator.discover_unique_called_functions() == [(0x100, 0x200)]
    assert db.is_match(0x100, 0x200)
    assert not db.is_match(0x110, 0x210)
