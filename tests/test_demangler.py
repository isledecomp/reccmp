import pytest
from reccmp.isledecomp.cvdump.demangler import (
    demangle_string_const,
    demangle_vtable,
    parse_encoded_number,
    InvalidEncodedNumberError,
    get_vtordisp_name,
)

string_demangle_cases = [
    ("??_C@_08LIDF@December?$AA@", 8, False),
    ("??_C@_0L@EGPP@english?9nz?$AA@", 11, False),
    (
        "??_C@_1O@POHA@?$AA?$CI?$AAn?$AAu?$AAl?$AAl?$AA?$CJ?$AA?$AA?$AA?$AA?$AA?$AH?$AA?$AA?$AA?$AA?$AA?$AA?$AA?$9A?$AE?$;I@",
        14,
        True,
    ),
    ("??_C@_00A@?$AA@", 0, False),
    ("??_C@_01A@?$AA?$AA@", 1, False),
]


@pytest.mark.parametrize("symbol, strlen, is_utf16", string_demangle_cases)
def test_strings(symbol, is_utf16, strlen):
    s = demangle_string_const(symbol)
    assert s is not None
    assert s.len == strlen
    assert s.is_utf16 == is_utf16


encoded_numbers = [
    ("A@", 0),
    ("AA@", 0),  # would never happen?
    ("P@", 15),
    ("BA@", 16),
    ("BCD@", 291),
]


@pytest.mark.parametrize("string, value", encoded_numbers)
def test_encoded_numbers(string, value):
    assert parse_encoded_number(string) == value


def test_invalid_encoded_number():
    with pytest.raises(InvalidEncodedNumberError):
        parse_encoded_number("Hello")


vtable_cases = [
    ("??_7LegoCarBuildAnimPresenter@@6B@", "LegoCarBuildAnimPresenter::`vftable'"),
    ("??_7?$MxCollection@PAVLegoWorld@@@@6B@", "MxCollection<LegoWorld *>::`vftable'"),
    (
        "??_7?$MxPtrList@VLegoPathController@@@@6B@",
        "MxPtrList<LegoPathController>::`vftable'",
    ),
    ("??_7Renderer@Tgl@@6B@", "Tgl::Renderer::`vftable'"),
    ("??_7LegoExtraActor@@6B0@@", "LegoExtraActor::`vftable'{for `LegoExtraActor'}"),
    (
        "??_7LegoExtraActor@@6BLegoAnimActor@@@",
        "LegoExtraActor::`vftable'{for `LegoAnimActor'}",
    ),
    (
        "??_7LegoAnimActor@@6B?$LegoContainer@PAM@@@",
        "LegoAnimActor::`vftable'{for `LegoContainer<float *>'}",
    ),
]


@pytest.mark.parametrize("symbol, class_name", vtable_cases)
def test_vtable(symbol, class_name):
    assert demangle_vtable(symbol) == class_name


def test_vtordisp():
    """Make sure we can accurately detect an adjuster thunk symbol"""
    assert get_vtordisp_name("") is None
    assert get_vtordisp_name("?ClassName@LegoExtraActor@@UBEPBDXZ") is None
    assert (
        get_vtordisp_name("?ClassName@LegoExtraActor@@$4PPPPPPPM@A@BEPBDXZ") is not None
    )

    # A function called vtordisp
    assert get_vtordisp_name("?vtordisp@LegoExtraActor@@UBEPBDXZ") is None
