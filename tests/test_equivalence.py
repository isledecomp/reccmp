"""Tests for fold-aware equivalence groups: parsing, name canonicalization,
and vtable-slot pairing through proven-equivalent original addresses."""

from pathlib import PurePath

import pytest

from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb
from reccmp.compare.equivalence import canonical_orig_addr, parse_equivalence_groups
from reccmp.compare.asm.replacement import (
    create_name_lookup,
    NameReplacementProtocol,
)
from reccmp.cvdump.types import CvdumpTypeKey
from reccmp.formats.textfile import TextFile


def textfile(text: str) -> TextFile:
    return TextFile(PurePath("groups.csv"), text)


#### parse_equivalence_groups ####


def test_parse_basic_rows():
    groups = parse_equivalence_groups(
        [
            textfile(
                "# comment line\n"
                "\n"
                "0x00430380|0x0048a9d0|TTreatiesView::~TTreatiesView|folded_symbol_group\n"
                "0x00426ec0|0x00479b00\n"
            )
        ]
    )
    assert groups == {0x430380: 0x48A9D0, 0x426EC0: 0x479B00}


def test_parse_skips_malformed_and_self_rows():
    groups = parse_equivalence_groups(
        [
            textfile(
                "just-one-field\n"
                "notahex|0x1000\n"
                "0x2000|0x2000\n"  # member == canonical
                "0x3000|0x4000\n"
            )
        ]
    )
    assert groups == {0x3000: 0x4000}


def test_parse_flattens_chains():
    groups = parse_equivalence_groups([textfile("0x1000|0x2000\n0x2000|0x3000\n")])
    assert groups[0x1000] == 0x3000
    assert groups[0x2000] == 0x3000


def test_parse_keeps_first_on_conflict():
    groups = parse_equivalence_groups([textfile("0x1000|0x2000\n0x1000|0x3000\n")])
    assert groups == {0x1000: 0x2000}


def test_canonical_orig_addr():
    groups = {0x1000: 0x2000}
    assert canonical_orig_addr(groups, 0x1000) == 0x2000
    assert canonical_orig_addr(groups, 0x2000) == 0x2000
    assert canonical_orig_addr(groups, 0x9999) == 0x9999


#### name canonicalization in create_name_lookup ####


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def create_lookup(
    db: EntityDb,
    image_id: ImageId,
    groups: dict[int, int] | None = None,
) -> NameReplacementProtocol:
    def bin_lookup(_: int) -> int | None:
        return None

    def offset_lookup(_: CvdumpTypeKey, __: int) -> str:
        return ""

    return create_name_lookup(db, image_id, bin_lookup, offset_lookup, groups)


def make_folded_db(db: EntityDb) -> None:
    """Original: fold island 0x1000 (leaf dtor claim) + shared final 0x2000.
    Recomp: leaf dtor body 0x5000 paired with the island; shared body 0x6000
    paired with the final."""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 0x1000, name="Leaf::~Leaf", type=EntityType.FUNCTION.value
        )
        batch.set(
            ImageId.ORIG, 0x2000, name="Base::~Base", type=EntityType.FUNCTION.value
        )
        batch.match(0x1000, 0x5000)
        batch.match(0x2000, 0x6000)


def test_orig_member_and_recomp_leaf_emit_canonical_name(db: EntityDb):
    """orig `call island` and recomp `call leaf-dtor` both canonicalize to the
    shared final body's name, so the operands compare equal."""
    make_folded_db(db)
    groups = {0x1000: 0x2000}

    orig_lookup = create_lookup(db, ImageId.ORIG, groups)
    recomp_lookup = create_lookup(db, ImageId.RECOMP, groups)

    orig_name = orig_lookup(0x1000, exact=True)
    recomp_name = recomp_lookup(0x5000, exact=True)
    assert orig_name is not None
    assert "Base::~Base" in orig_name
    assert orig_name == recomp_name


def test_canonical_reference_matches_member_reference(db: EntityDb):
    """orig `call <shared final>` vs recomp `call <leaf dtor>`: the leaf's
    original address is a group member, so both emit the canonical name."""
    make_folded_db(db)
    groups = {0x1000: 0x2000}

    orig_lookup = create_lookup(db, ImageId.ORIG, groups)
    recomp_lookup = create_lookup(db, ImageId.RECOMP, groups)

    assert orig_lookup(0x2000, exact=True) == recomp_lookup(0x5000, exact=True)


def test_no_groups_keeps_own_names(db: EntityDb):
    make_folded_db(db)

    orig_lookup = create_lookup(db, ImageId.ORIG)
    recomp_lookup = create_lookup(db, ImageId.RECOMP)

    orig_name = orig_lookup(0x1000, exact=True)
    recomp_name = recomp_lookup(0x5000, exact=True)
    assert orig_name is not None
    assert "Leaf::~Leaf" in orig_name
    assert orig_name == recomp_name  # same entity, name unchanged


def test_non_member_unaffected_by_groups(db: EntityDb):
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0x3000, name="Other", type=EntityType.FUNCTION.value)
    lookup = create_lookup(db, ImageId.ORIG, {0x1000: 0x2000})
    name = lookup(0x3000, exact=True)
    assert name is not None
    assert "Other" in name


def test_member_with_unnamed_canonical_falls_back(db: EntityDb):
    """A member whose canonical entity has no name keeps its own name."""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 0x1000, name="Leaf::~Leaf", type=EntityType.FUNCTION.value
        )
        batch.set(ImageId.ORIG, 0x2000)  # no name
    lookup = create_lookup(db, ImageId.ORIG, {0x1000: 0x2000})
    name = lookup(0x1000, exact=True)
    assert name is not None
    assert "Leaf::~Leaf" in name


#### folded-island function rows score as effective ####


def compare_island(
    db: EntityDb,
    orig: bytes,
    recomp: bytes,
    groups: dict[int, int] | None = None,
):
    """Run FunctionComparator.compare_function with mocked binaries."""
    # pylint: disable=import-outside-toplevel
    from unittest.mock import Mock

    from reccmp.compare.functions import FunctionComparator
    from reccmp.compare.lines import LinesDb
    from reccmp.compare.event import ReccmpReportProtocol
    from reccmp.compare.db import ReccmpMatch
    from reccmp.cvdump.types import CvdumpTypesParser

    orig_bin = Mock(spec=[])
    orig_bin.read = Mock(return_value=orig)
    orig_bin.imagebase = 0
    orig_bin.is_relocated_addr = Mock(return_value=False)
    orig_bin.is_debug = Mock(return_value=False)

    recomp_bin = Mock(spec=[])
    recomp_bin.read = Mock(return_value=recomp)
    recomp_bin.imagebase = 0
    recomp_bin.is_relocated_addr = Mock(return_value=False)
    recomp_bin.is_debug = Mock(return_value=False)

    comp = FunctionComparator(
        db,
        LinesDb(),
        orig_bin,
        recomp_bin,
        Mock(spec=ReccmpReportProtocol),
        CvdumpTypesParser(),
        equivalence_groups=groups or {},
    )
    return comp.compare_function(
        ReccmpMatch(
            0x200,
            0x400,
            {
                "type": 1,
                "stub": False,
                "name": "unittest",
                "symbol": "?Unittest",
                "recomp_size": len(recomp),
            },
        )
    )


REAL_BODY = bytes.fromhex("558bec5dc3")  # push ebp / mov ebp,esp / pop ebp / ret
JMP_ISLAND = bytes.fromhex("e9fb060000")  # jmp rel32


def test_island_row_scores_effective(db: EntityDb):
    result = compare_island(db, JMP_ISLAND, REAL_BODY, groups={0x200: 0x900})
    assert result.match_ratio < 1.0
    assert result.analysis.is_effective
    assert "folded_symbol_alias" in result.analysis.effective_reasons


def test_island_row_with_padding_scores_effective(db: EntityDb):
    result = compare_island(
        db, JMP_ISLAND + b"\x90\xcc\x90", REAL_BODY, groups={0x200: 0x900}
    )
    assert result.analysis.is_effective


def test_island_shape_without_group_membership_stays_unproven(db: EntityDb):
    result = compare_island(db, JMP_ISLAND, REAL_BODY, groups={0x999: 0x900})
    assert not result.analysis.is_effective


def test_non_island_group_member_not_blessed(db: EntityDb):
    """A group member whose original body is NOT a bare jmp island must go
    through the normal comparison (no blanket equivalence)."""
    other_body = bytes.fromhex("33c0c3")  # xor eax,eax / ret
    result = compare_island(db, other_body, REAL_BODY, groups={0x200: 0x900})
    assert not result.analysis.is_effective
