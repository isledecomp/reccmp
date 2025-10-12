from reccmp.ghidra.importer.entity_names import sanitize_name


def test_sanitize_name():
    assert sanitize_name("abc") == ((), "abc")
    assert sanitize_name("abc::def::ghi") == (("abc", "def"), "ghi")
    assert sanitize_name("abc<def>") == ((), "abc[def]")
    assert sanitize_name("Map<char const *,ViewLODList *,ROINameComparator>") == (
        (),
        "Map[char_const_#,ViewLODList_#,ROINameComparator]",
    )
    assert sanitize_name("LegoRace::`scalar deleting destructor'") == (
        ("LegoRace",),
        "'scalar_deleting_destructor'",
    )
    # shortened from a real case. The cutoff at the end actually happens
    assert sanitize_name(
        "_Tree<map<allocator<LegoCharacter *> >::_Kfn,map<char *,LegoCha"
    ) == ((), "_Tree[map[allocator[LegoCharacter_#]_]::_Kfn,map[char_#,LegoCha")
    assert sanitize_name("a<b::c>::d<e::f<g::h>>::i") == (
        ("a[b::c]", "d[e::f[g::h]]"),
        "i",
    )
    assert sanitize_name("Thunk of 'Helicopter::CreateState'") == (
        ("Helicopter",),
        "_thunk_CreateState",
    )
