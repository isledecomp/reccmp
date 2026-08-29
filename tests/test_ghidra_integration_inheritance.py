"""Tests for importing classes with various inheritance patterns.

Parent classes are embedded in the struct for the derived class instead of
copying their members instead.

Vftable pointers are set to offset 0 of the class with virtual functions.

Classes with a direct virtual base class have an added VBasePtr* member
that points to the static Vbtable struct. This contains a list of offsets
from the derived class to each direct or indirect virtual base class.

To import classes with a parent that uses virtual inheritance, we need to
create a "slim" version of the base that includes only its "owned" members.

The classic example is: `C extends B`, `B virtually extends A`.
The expected layout for C is:

- Members introduced by B
- Members introduced by C
- Members introduced by A

We cannot reliably set offsets for A or its members without reading the vbtable
for B. This data is not currently available in the type importer.
"""

import pytest
from .cvdump_sample import load_cvdump_sample
from .ghidra_integration_test_setup import (
    GhidraTypeTestHelper,
    component,
    components_of,
    dereference,
)


def test_multiple_inheritance_base_offsets(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/multiple_inheritance.cpp

        A           size 12
        B           size 12
        C : A, B    size 28

    Should create full-sized structs for A and B when creating C.
    """
    sample = load_cvdump_sample("multiple-inheritance")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-c"))

    assert leaf.getLength() == 28
    assert components_of(leaf) == [
        (0, "base", "A"),
        (12, "base_B", "B"),
        (24, "m_c0", "int"),
    ]


def test_duplicate_base_appears_twice(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/diamond_duplicate.cpp

        A           size 8
        B : A       size 12
        C : A       size 12
        D : B, C    size 28

    Diamond inheritance pattern.
    B and C each have their own copy of parent A. D extends both B and C, and
    so it has two copies of A.
    """
    sample = load_cvdump_sample("diamond-duplicate")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-d"))

    assert leaf.getLength() == 28
    assert components_of(leaf) == [
        (0, "base", "B"),
        (12, "base_C", "C"),
        (24, "m_d0", "int"),
    ]

    assert components_of(component(leaf, 0)) == [
        (0, "base", "A"),
        (8, "m_b0", "int"),
    ]
    assert components_of(component(leaf, 12)) == [
        (0, "base", "A"),
        (8, "m_c0", "int"),
    ]


def test_base_offsets_are_not_a_sum_of_sizes(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/base_padding.cpp

        A              size 1
        B              size 8
        C              size 8
        D : A, B, C    size 32

    Use the offsets given in the field list for D when setting the position for
    base classes. This is most important for A, because of the padding between
    A and its sibling B. The struct for A does not include this padding.
    """
    sample = load_cvdump_sample("base-padding")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-d"))

    assert leaf.getLength() == 32
    assert components_of(leaf) == [
        (0, "base", "A"),
        (4, "base_B", "B"),
        (16, "base_C", "C"),
        (24, "m_d0", "int"),
    ]

    # Structs created for each parent do not include padding.
    assert component(leaf, 0).getLength() == 1
    assert component(leaf, 4).getLength() == 8
    assert component(leaf, 16).getLength() == 8


def test_slim_vbase_at_offset_zero(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_simple.cpp

        A                size 8
        B : virtual A    size 16
        C : B            size 20

    B is 16 bytes because it contains its own members (8 bytes) followed by A.
    The field list for C places C's first member at offset 8. Therefore, the
    full-sized B will not fit and we need to create a "slim" copy.
    """
    sample = load_cvdump_sample("vbase-simple")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-c"))

    assert leaf.getLength() == 20
    assert components_of(leaf) == [
        (0, "base", "B_vbase_slim"),
        (8, "m_c0", "int"),
        # A?
    ]

    slim = component(leaf, 0)
    assert slim.getLength() == 8
    assert components_of(slim) == [
        (0, "vbase_offset", "VBasePtr *"),
        (4, "m_b0", "int"),
    ]

    class_b = type_helper.type_importer.import_pdb_type_into_ghidra(
        sample.key("class-b")
    )

    # Although they have the same members, the full-size B and the slim B are different types.
    # (Full-size B should have members from A, but does not due to the acknowledged vbtable limitation.)
    assert class_b != slim

    assert class_b.getLength() == 16
    assert components_of(class_b) == [
        (0, "vbase_offset", "VBasePtr *"),
        (4, "m_b0", "int"),
        # A?
    ]


def test_slim_vbase_as_first_base(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_first_base.cpp

        A                size 8
        B : virtual A    size 16
        C                size 12
        D : B, C         size 32

    B needs a slim copy because it has a virtual base.
    C has no virtual base, so the full-sized C fits at offset 8 in D.
    D has no direct virtual base, so it does not get a vbase pointer.
    """
    sample = load_cvdump_sample("vbase-first-base")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-d"))

    assert leaf.getLength() == 32
    assert components_of(leaf) == [
        (0, "base", "B_vbase_slim"),
        (8, "base_C", "C"),
        (20, "m_d0", "int"),
        # A?
    ]

    slim_b = component(leaf, 0)
    assert slim_b.getLength() == 8
    assert components_of(slim_b) == [
        (0, "vbase_offset", "VBasePtr *"),
        (4, "m_b0", "int"),
    ]

    class_c = component(leaf, 8)
    assert class_c.getLength() == 12
    assert components_of(class_c) == [
        (0, "m_c0", "int"),
        (4, "m_c1", "int"),
        (8, "m_c2", "int"),
    ]


def test_slim_vbase_at_nonzero_offset(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_second_base.cpp

        A                size 8
        B                size 12
        C : virtual A    size 16
        D : B, C         size 32

    C needs a slim copy because it has a virtual base. The copy is at offset 12
    because B occupies the first 12 bytes.
    B has no virtual base, so the full-sized B fits at offset 0 in D.
    D has no direct virtual base, so it does not get a vbase pointer.
    """
    sample = load_cvdump_sample("vbase-second-base")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-d"))

    assert leaf.getLength() == 32
    assert components_of(leaf) == [
        (0, "base", "B"),
        (12, "base_C_vbase_slim", "C_vbase_slim"),
        (20, "m_d0", "int"),
        # A?
    ]

    class_b = component(leaf, 0)
    assert class_b.getLength() == 12
    assert components_of(class_b) == [
        (0, "m_b0", "int"),
        (4, "m_b1", "int"),
        (8, "m_b2", "int"),
    ]

    slim_c = component(leaf, 12)
    assert slim_c.getLength() == 8
    assert components_of(slim_c) == [
        (0, "vbase_offset", "VBasePtr *"),
        (4, "m_c0", "int"),
        # A?
    ]


def test_slim_base_ends_at_last_member(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_alignment.cpp

        A                size 16
        B : virtual A    size 32
        C : B            size 32

    In C, there is padding between the slim copy of B and the first C member.
    The slim copy of B does not contain this padding.
    """
    sample = load_cvdump_sample("vbase-alignment")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-c"))

    assert components_of(leaf) == [
        (0, "base", "B_vbase_slim"),
        (12, "m_c0", "char"),
        # A?
    ]

    assert leaf.getLength() == 32

    slim = component(leaf, 0)
    assert components_of(slim) == [
        (0, "vbase_offset", "VBasePtr *"),
        (4, "m_b0", "int"),
        (8, "m_b1", "char"),
    ]
    assert slim.getLength() == 9


def test_diamond_shares_one_virtual_base(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/diamond_virtual.cpp

        A                size 8
        B : virtual A    size 16
        C : virtual A    size 16
        D : B, C         size 28

    Diamond inheritance pattern with virtual inheritance.
    D contains only one copy of A: B and C point to the single A
    using their vbtables.
    """
    sample = load_cvdump_sample("diamond-virtual")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-d"))

    assert leaf.getLength() == 28
    assert components_of(leaf) == [
        (0, "base", "B_vbase_slim"),
        (8, "base_C_vbase_slim", "C_vbase_slim"),
        (16, "m_d0", "int"),
    ]

    slim_b = component(leaf, 0)
    assert components_of(slim_b) == [
        (0, "vbase_offset", "VBasePtr *"),
        (4, "m_b0", "int"),
    ]

    slim_c = component(leaf, 8)
    assert components_of(slim_c) == [
        (0, "vbase_offset", "VBasePtr *"),
        (4, "m_c0", "int"),
    ]

    vbase_ptr_b = dereference(component(slim_b, 0))
    vbase_ptr_c = dereference(component(slim_c, 0))

    # Despite the name, these are not the same `VBasePtr`.
    assert vbase_ptr_b != vbase_ptr_c

    assert components_of(vbase_ptr_b) == [
        (0, "o_self", "B_vbase_slim *"),
        (4, "o_A", "APtrOffset"),
    ]
    assert components_of(vbase_ptr_c) == [
        (0, "o_self", "C_vbase_slim *"),
        (4, "o_A", "APtrOffset"),
    ]


def test_direct_virtual_base_at_nonzero_vbpoff(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_after_base.cpp

        A                   size 8
        B                   size 12
        C : B, virtual A    size 28

    We cannot naively assume that any class with a direct virtual base has
    vbpoff at offset zero. Here, C's non-virtual base class B is first.
    B has no virtual base of its own, so the full-sized B fits at offset 0.
    """
    sample = load_cvdump_sample("vbase-after-base")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-c"))

    assert leaf.getLength() == 28
    assert components_of(leaf) == [
        (0, "base", "B"),
        (12, "vbase_offset", "VBasePtr *"),
        (16, "m_c0", "int"),
    ]

    assert component(leaf, 0).getLength() == 12

    vbase_ptr = dereference(component(leaf, 12))
    assert components_of(vbase_ptr) == [
        (0, "o_self", "C *"),
        (4, "o_A", "APtrOffset"),
    ]


def test_vbaseptr_slots_for_two_virtual_bases(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_two.cpp

        A                           size 8
        B                           size 4
        C : virtual A, virtual B    size 20

    The vbtable for C has two entries, one for each virtual base.
    """
    sample = load_cvdump_sample("vbase-two")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-c"))

    assert leaf.getLength() == 20
    assert components_of(leaf) == [
        (0, "vbase_offset", "VBasePtr *"),
        (4, "m_c0", "int"),
        # A?
        # B?
    ]

    vbase_ptr = dereference(component(leaf, 0))
    assert components_of(vbase_ptr) == [
        (0, "o_self", "C *"),
        (4, "o_A", "APtrOffset"),
        (8, "o_B", "BPtrOffset"),
    ]


def test_chained_virtual_bases(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_chain.cpp

        A                size 8
        B : virtual A    size 16
        C : virtual B    size 24
        D : virtual C    size 32

    The vbtable for D has three entries. The order must match the vbind index
    values for each virtual base, not the order they appear in the field list.
    """
    sample = load_cvdump_sample("vbase-chain")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-d"))

    assert leaf.getLength() == 32
    assert components_of(leaf) == [
        (0, "vbase_offset", "VBasePtr *"),
        (4, "m_d0", "int"),
        # A?
        # B?
        # C?
    ]

    vbase_ptr = dereference(component(leaf, 0))
    assert components_of(vbase_ptr) == [
        (0, "o_self", "D *"),
        (4, "o_A", "APtrOffset"),
        (8, "o_B", "BPtrOffset"),
        (12, "o_C", "CPtrOffset"),
    ]


def test_slim_vbase_with_vftable(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_vftable.cpp

        A                size 8
        B : virtual A    size 20
        C : B            size 24

    B declares both a virtual function and a virtual base, so it carries a
    vftable pointer and a vbase pointer. LF_VFUNCTAB has no offset, so we place
    the vftable pointer at 0 by assumption. The field list gives vbpoff = 4,
    which is where the vbase pointer lands once the vftable takes the first four
    bytes. This is the only sample where the assumed offset and an offset we
    read could collide.

    B's slim copy keeps both pointers, so it is 12 bytes rather than 8, and C's
    own member starts at 12.
    """
    sample = load_cvdump_sample("vbase-vftable")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-c"))

    assert leaf.getLength() == 24
    assert components_of(leaf) == [
        (0, "base", "B_vbase_slim"),
        (12, "m_c0", "int"),
    ]

    slim = component(leaf, 0)
    assert slim.getLength() == 12
    assert components_of(slim) == [
        (0, "vftable", "void *"),
        (4, "vbase_offset", "VBasePtr *"),
        (8, "m_b0", "int"),
    ]


def test_multiple_inheritance_with_virtual_functions(
    type_helper: GhidraTypeTestHelper,
):
    """cvdump_sample/cpp/multiple_inheritance_virtual_functions.cpp

        A           size 12
        B           size 8
        C : A, B    size 24

    A, B, and C each introduce a virtual function.
    C's virtual function is combined in A's vtable at offset 0 in C.
    The vtable for B's functions is at offset 12 in C.
    """
    sample = load_cvdump_sample("multiple-inheritance-virtual-functions")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-c"))

    assert leaf.getLength() == 24
    assert components_of(leaf) == [
        (0, "base", "A"),
        (12, "base_B", "B"),
        (20, "m_c0", "int"),
    ]

    assert components_of(component(leaf, 0)) == [
        (0, "vftable", "void *"),
        (4, "m_a0", "int"),
        (8, "m_a1", "int"),
    ]
    assert components_of(component(leaf, 12)) == [
        (0, "vftable", "void *"),
        (4, "m_b0", "int"),
    ]


@pytest.mark.xfail(reason="The importer does not place virtual base classes yet")
def test_padding_between_two_virtual_bases(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_padding.cpp

        A                           size 8
        B                           size 1
        C : virtual A, virtual B    size 25
        D : virtual B, virtual A    size 32

    The importer does not currently set the offset of a virtual base class.
    The offsets are not given in any of the PDB data. We would need to read the
    static vbtable (referenced by VBasePtr*) to position a base accurately.
    Note the difference in size between C and D, which extend A and B in
    different orders. In the case of D, there is padding between B and A.
    We cannot set the correct offsets by simply adding the size of B and A.
    We could guess the default byte alignment but a `#pragma pack` directive
    will change this without any indication that this has happened.
    """
    sample = load_cvdump_sample("vbase-padding")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-d"))

    assert leaf.getLength() == 32
    assert components_of(leaf) == [
        (0, "vbase_offset", "VBasePtr *"),
        (8, "m_d0", "double"),
        (16, "vbase_B", "B"),
        (24, "vbase_A", "A"),
    ]


@pytest.mark.xfail(reason="The importer does not place virtual base classes yet")
def test_no_padding_between_two_virtual_bases(type_helper: GhidraTypeTestHelper):
    """cvdump_sample/cpp/vbase_padding_packed.cpp

        A                           size 8
        B                           size 1
        C : virtual A, virtual B    size 25
        D : virtual B, virtual A    size 25

    These are the same classes as `vbase_padding.cpp`, but wrapped with
    `#pragma pack(1)`. This causes the `PACKED` attribute to appear in each
    LF_CLASS. In this case, we could place the virtual bases reliably because
    simply adding the struct size would be correct.
    """
    sample = load_cvdump_sample("vbase-padding-packed")
    type_helper.set_up_cvdump_types(sample.text)
    leaf = type_helper.type_importer.import_pdb_type_into_ghidra(sample.key("class-d"))

    assert leaf.getLength() == 32
    assert components_of(leaf) == [
        (0, "vbase_offset", "VBasePtr *"),
        (8, "m_d0", "double"),
        (16, "vbase_B", "B"),
        (17, "vbase_A", "A"),
    ]
