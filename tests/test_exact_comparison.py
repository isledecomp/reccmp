from reccmp.compare.exact import compare_relocation_masked, mask_relocations, stable_ranges


def test_relocation_masked_exact_comparison_reports_mode() -> None:
    result = compare_relocation_masked(
        b"\x55\x11\x22\x33\x44\xc3",
        b"\x55\xaa\xbb\xcc\xdd\xc3",
        recompiled_relocations=(1,),
    )

    assert result.exact
    assert result.status == "exact"
    assert result.exact_mode == "relocation-masked-object"
    assert result.stable_bytes == 2


def test_exact_comparison_honours_function_extent() -> None:
    result = compare_relocation_masked(b"\x90\xc3", b"\x90\xc3\x00\x01", size=2)
    assert result.exact
    assert result.original_size == 2
    assert result.recompiled_size == 4


def test_stable_ranges_and_masking_clip_invalid_relocations() -> None:
    assert stable_ranges(8, (-2, 2, 7)) == [(0, 2), (6, 8)]
    assert mask_relocations(b"abcdefgh", (-2, 2, 7)) == b"ab\0\0\0\0gh"
