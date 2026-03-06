"""Smoke tests for MSVC C++ symbol demangler, based on the demumble library.
This is here to spot changes for the functions that depend on this output."""

import pytest
from reccmp.cvdump.demangler import msvc_demangle

# pylint:disable=line-too-long
MSVC_DEMANGLE_SAMPLES = (
    (
        # Symbol longer than 255 chars
        "??0?$reverse_bidirectional_iterator@Viterator@?$_Tree@PAVMxAtom@@PAV1@U_Kfn@?$set@PAVMxAtom@@UMxAtomCompare@@V?$allocator@PAVMxAtom@@@@@@UMxAtomCompare@@V?$allocator@PAVMxAtom@@@@@@PAVMxAtom@@AAPAV3@PAPAV3@H@@QAE@Viterator@?$_Tree@PAVMxAtom@@PAV1@U_Kfn@?$set@PAVMxAtom@@UMxAtomCompare@@V?$allocator@PAVMxAtom@@@@@@UMxAtomCompare@@V?$allocator@PAVMxAtom@@@@@@@Z",
        "public: __thiscall reverse_bidirectional_iterator<class _Tree<class MxAtom *, class MxAtom *, struct set<class MxAtom *, struct MxAtomCompare, class allocator<class MxAtom *>>::_Kfn, struct MxAtomCompare, class allocator<class MxAtom *>>::iterator, class MxAtom *, class MxAtom *&, class MxAtom **, int>::reverse_bidirectional_iterator<class _Tree<class MxAtom *, class MxAtom *, struct set<class MxAtom *, struct MxAtomCompare, class allocator<class MxAtom *>>::_Kfn, struct MxAtomCompare, class allocator<class MxAtom *>>::iterator, class MxAtom *, class MxAtom *&, class MxAtom **, int>(class _Tree<class MxAtom *, class MxAtom *, struct set<class MxAtom *, struct MxAtomCompare, class allocator<class MxAtom *>>::_Kfn, struct MxAtomCompare, class allocator<class MxAtom *>>::iterator)",
    ),
    (
        # Truncated version of above symbol. Long symbols are only available in .cpp.s generated asm.
        "??0?$reverse_bidirectional_iterator@Viterator@?$_Tree@PAVMxAtom@@PAV1@U_Kfn@?$set@PAVMxAtom@@UMxAtomCompare@@V?$allocator@PAVMxAtom@@@@@@UMxAtomCompare@@V?$allocator@PAVMxAtom@@@@@@PAVMxAtom@@AAPAV3@PAPAV3@H@@QAE@Viterator@?$_Tree@PAVMxAtom@@PAV1@U_Kfn@?$",
        "",
    ),
    (
        # vtordisp
        "?ClassName@LegoExtraActor@@$4PPPPPPPM@A@BEPBDXZ",
        "[thunk]: public: virtual char const * __thiscall LegoExtraActor::ClassName`vtordisp{-4, 0}'(void) const",
    ),
    (
        "??8MxPalette@@QAEEAAV0@@Z",
        "public: unsigned char __thiscall MxPalette::operator==(class MxPalette &)",
    ),
    (
        "??_G?$MxListCursor@PAVLegoPathController@@@@UAEPAXI@Z",
        "public: virtual void * __thiscall MxListCursor<class LegoPathController *>::`scalar deleting dtor'(unsigned int)",
    ),
    (
        "?ConvertHSVToRGB@@YAXMMMPAM00@Z",
        "void __cdecl ConvertHSVToRGB(float, float, float, float *, float *, float *)",
    ),
    (
        # C symbol
        "_MemPoolCheck@4",
        "",
    ),
    (
        # C symbol
        "_fopen",
        "",
    ),
    (
        # vtable
        "??_7PizzaMissionState@@6B@",
        "const PizzaMissionState::`vftable'",
    ),
    (
        # vtable with namespace
        "??_7AlphaMask@MxVideoPresenter@@6B@",
        "const MxVideoPresenter::AlphaMask::`vftable'",
    ),
    (
        "??0AlphaMask@MxVideoPresenter@@QAE@ABVMxBitmap@@@Z",
        "public: __thiscall MxVideoPresenter::AlphaMask::AlphaMask(class MxBitmap const &)",
    ),
)


@pytest.mark.parametrize("symbol, result", MSVC_DEMANGLE_SAMPLES)
def test_demangle_samples(symbol, result):
    assert msvc_demangle(symbol) == result
