from pathlib import Path
from reccmp.compare.diff import RawDiffOutput
from reccmp.compare.report import ReccmpComparedEntity, ReccmpStatusReport
from reccmp.difflib import SequenceMatcher
from reccmp.types import EntityType
from reccmp.utils import write_html_report


def make_diff(
    orig: list[tuple[int, str]], recomp: list[tuple[int, str]]
) -> RawDiffOutput:
    """Diff two lists of (address, instruction text)."""
    return RawDiffOutput(
        codes=SequenceMatcher(
            None,
            [text for _, text in orig],
            [text for _, text in recomp],
            autojunk=False,
        ).get_opcodes(),
        orig_inst=[(hex(addr), text) for addr, text in orig],
        recomp_inst=[(hex(addr), text) for addr, text in recomp],
    )


def function(
    name: str,
    orig_addr: int,
    accuracy: float,
    *,
    recomp_addr: int | None = None,
    **kwargs,
) -> ReccmpComparedEntity:
    _recomp_addr = recomp_addr if recomp_addr is not None else orig_addr + 0x100000
    return ReccmpComparedEntity(
        orig_addr=orig_addr,
        name=name,
        accuracy=accuracy,
        type=EntityType.FUNCTION,
        recomp_addr=_recomp_addr,
        **kwargs,
    )


def diff_rows() -> list[ReccmpComparedEntity]:
    return [
        function("IsleApp::IsleApp", 0x401000, 1.0),
        function("IsleApp::Close", 0x401100, 1.0, is_stub=True),
        function(
            "IsleApp::Tick",
            0x401200,
            0.0,
            is_stub=True,
            rdiff=make_diff([(0x401200, "nop")], [(0x501200, "ret")]),
        ),
        function(
            "IsleApp::SetupVideoFlags",
            0x401300,
            0.75,
            rdiff=make_diff(
                [
                    (0x401300, "push ebp"),
                    (0x401301, "mov ebp, esp"),
                    (0x401303, "mov eax, dword ptr [ebp + 8]"),
                    (0x401306, "ret"),
                ],
                [
                    (0x501300, "push ebp"),
                    (0x501301, "mov ebp, esp"),
                    (0x501303, "mov eax, dword ptr [ebp + 0xc]"),
                    (0x501306, "ret"),
                ],
            ),
        ),
        function(
            "WndProc",
            0x401400,
            0.5,
            is_effective_match=True,
            rdiff=make_diff(
                [
                    (0x401400, "mov eax, dword ptr [ebp + 8]"),
                    (0x401403, "add eax, 1"),
                ],
                [
                    (0x501400, "mov ecx, dword ptr [ebp + 8]"),
                    (0x501403, "add ecx, 1"),
                ],
            ),
        ),
        function("Padding001", 0x401500, 0.5),
    ]


def diff_display() -> list[ReccmpComparedEntity]:
    return [
        function(
            "IsleApp::SetupVideoFlags",
            0x401000,
            0.75,
            rdiff=make_diff(
                [
                    (0x401000, "push ebp"),
                    (0x401001, "mov ebp, esp"),
                    (0x401003, "mov eax, dword ptr [ebp + 8]"),
                    (0x401006, "ret"),
                ],
                [
                    (0x501000, "push ebp"),
                    (0x501001, "mov ebp, esp"),
                    (0x501003, "mov eax, dword ptr [ebp + 0xc]"),
                    (0x501006, "ret"),
                ],
            ),
        ),
        function(
            "@_shi_resizeVar@8",
            0x401100,
            0.5,
            rdiff=make_diff(
                [(0x401100, "xor eax, eax"), (0x401102, "ret")],
                [(0x501100, "sub eax, eax"), (0x501102, "ret")],
            ),
        ),
        function(
            "@_shi_taskRemovePool@4",
            0x401200,
            0.5,
            rdiff=make_diff(
                [(0x401200, "xor ecx, ecx"), (0x401202, "ret")],
                [(0x501200, "sub ecx, ecx"), (0x501202, "ret")],
            ),
        ),
    ]


def column_header() -> list[ReccmpComparedEntity]:
    """Should create entities that sort differently by address or by name."""
    return [
        function("list<ROI *,allocator<ROI *> >::_Buynode", 0x401000, 1.0),
        function("??2@YAPAXI@Z", 0x401100, 1.0),
        function("IsleApp::IsleApp", 0x8005D7, 1.0),
    ]


def single_function() -> list[ReccmpComparedEntity]:
    """Intended for tests that do not exercise searching or filtering behavior."""
    return [function("Function", 0x401000, 1.0)]


def entity_table() -> list[ReccmpComparedEntity]:
    return [
        function("Vector2::MulImpl(float const &)", 0x401000, 1.0),
        function("list<ROI *,allocator<ROI *> >::_Buynode", 0x401100, 1.0),
        function("MxParam::`scalar deleting destructor'", 0x401200, 1.0),
        function(
            "WndProc",
            0x401300,
            0.5,
            is_effective_match=True,
            rdiff=make_diff(
                [
                    (0x401300, "mov eax, dword ptr [ebp + 8]"),
                    (0x401303, "add eax, 1"),
                ],
                [
                    (0x501300, "mov ecx, dword ptr [ebp + 8]"),
                    (0x501303, "add ecx, 1"),
                ],
            ),
        ),
    ]


def search_bar() -> list[ReccmpComparedEntity]:
    """The test expects only one entity to contain `mov eax` instructions."""
    return [
        function(
            "IsleApp::SetupVideoFlags",
            0x401000,
            0.5,
            rdiff=make_diff(
                [(0x401000, "mov eax, 1"), (0x401005, "ret")],
                [(0x501000, "mov eax, 2"), (0x501005, "ret")],
            ),
        ),
        function("IsleApp::IsleApp", 0x401100, 1.0),
        function("WndProc", 0x401200, 1.0),
    ]


def table_option() -> list[ReccmpComparedEntity]:
    return [
        function("Matching", 0x401000, 1.0),
        function("Stub", 0x401100, 0.0, is_stub=True),
        function("Diff", 0x401200, 0.5),
    ]


def pagination() -> list[ReccmpComparedEntity]:
    """Should create enough entities to cover multiple pages. Default page size is 200."""
    return [
        function("IsleApp::IsleApp", 0x401000, 1.0),
        *[function(f"Function{i:03}", 0x401010 + 0x10 * i, 1.0) for i in range(499)],
    ]


SCENARIOS = {
    "diffRows": diff_rows,
    "diffDisplay": diff_display,
    "columnHeader": column_header,
    "pagination": pagination,
    "singleFunction": single_function,
    "entityTable": entity_table,
    "searchBar": search_bar,
    "tableOption": table_option,
}


def main():
    output_dir = Path(__file__).resolve().parent / "testdata"
    output_dir.mkdir(exist_ok=True)

    for name, entities in SCENARIOS.items():
        report = ReccmpStatusReport(filename="isle.exe")
        for e in entities():
            report.add_match(e)

        html_path = output_dir / f"{name}.html"
        write_html_report(str(html_path), report)
        print(html_path)


if __name__ == "__main__":
    main()
