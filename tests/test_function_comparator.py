from typing import Callable
from unittest.mock import Mock
import pytest
from reccmp.isledecomp.compare.db import EntityDb, ReccmpMatch
from reccmp.isledecomp.compare.diff import DiffReport
from reccmp.isledecomp.compare.event import ReccmpEvent, ReccmpReportProtocol
from reccmp.isledecomp.compare.functions import FunctionComparator
from reccmp.isledecomp.types import EntityType


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.fixture(name="report")
def fixture_report_mock() -> ReccmpReportProtocol:
    return Mock(spec=ReccmpReportProtocol)


ORIG_GLOBAL_OFFSET = 0x200
RECOMP_GLOBAL_OFFSET = 0x400


def compare_functions(
    db: EntityDb,
    orig: bytes,
    recomp: bytes,
    report: ReccmpReportProtocol,
    is_relocated_addr: Callable[[int], bool] | None = None,
) -> DiffReport:
    """Executes `FunctionComparator.compare_function` on the provided binary code."""

    # Do not use `spec=PEImage`. It may have default implementations that don't do what you expect
    # (like functions that always return `True`).
    orig_bin = Mock(spec=[])
    orig_bin.read = Mock(return_value=orig)
    orig_bin.imagebase = 0
    orig_bin.is_relocated_addr = is_relocated_addr or Mock(return_value=False)
    orig_bin.is_debug = Mock(return_value=False)

    recomp_bin = Mock(spec=[])
    recomp_bin.read = Mock(return_value=recomp)
    recomp_bin.imagebase = 0
    recomp_bin.is_relocated_addr = is_relocated_addr or Mock(return_value=False)
    recomp_bin.is_debug = Mock(return_value=False)

    comp = FunctionComparator(db, orig_bin, recomp_bin, report, "unittest")

    return comp.compare_function(
        ReccmpMatch(
            ORIG_GLOBAL_OFFSET,
            RECOMP_GLOBAL_OFFSET,
            f'{{"type":1,"stub":false,"name":"unittest","symbol":"?Unittest","size":{len(recomp)}}}',
        )
    )


def add_line_annotation(
    db: EntityDb,
    offset_from_function_start_orig: int,
    offset_from_function_start_recomp: int,
):
    """Adds a `// LINE:` annotation to the database."""

    orig_addr = ORIG_GLOBAL_OFFSET + offset_from_function_start_orig
    recomp_addr = RECOMP_GLOBAL_OFFSET + offset_from_function_start_recomp
    db.set_recomp_symbol(
        recomp_addr, name="cppfile.cpp:384", filename="src\\cppfile.cpp", line=384
    )
    db.set_pair(orig_addr, recomp_addr, EntityType.LINE)


def test_simple_identical_diff(db: EntityDb, report: ReccmpReportProtocol):
    # based on BETA10 0x1013e61d
    code = b"U\x8b\xec\x83\xec,SVWf\xc7E\xf8\x00\x00f\xc7E\xf0\x00\x00\x8bE\x14"

    diffreport = compare_functions(db, code, code, report)

    assert diffreport.ratio == 1.0
    assert diffreport.udiff == []


def test_simple_nontrivial_diff(db: EntityDb, report: ReccmpReportProtocol):
    orig = b"f\xc7E\xf8\x00\x00f\xc7E\xf0\x00\x00\x8b\x45\x14"
    # one instruction modified
    recm = b"f\xc7E\xf8\x00\x00f\xc7E\xf0\x00\x00\x8b\x51\x14"

    diffreport = compare_functions(db, orig, recm, report)

    assert diffreport.ratio < 1.0

    assert diffreport.udiff == [
        (
            "@@ -0x200,3 +0x400,3 @@",
            [
                {
                    "both": [
                        ("0x200", "mov word ptr [ebp - 8], 0", "0x400"),
                        ("0x206", "mov word ptr [ebp - 0x10], 0", "0x406"),
                    ]
                },
                {
                    "orig": [("0x20c", "mov eax, dword ptr [ebp + 0x14]")],
                    "recomp": [("0x40c", "mov edx, dword ptr [ecx + 0x14]")],
                },
            ],
        )
    ]


# Based on BETA10 0x1013e673
LINE_MISMATCH_EXAMPLE_ORIG = (
    b"+\xc8If\x89M\xd8\xe9\xd1\x01\x00\x00\xe9\x0e\x00\x00\x00\x0f\xbfE\xe8\x0f\xbfM\xd8\x03\xc1f\x89E\xd8\x8bE\xecf\x8b\x00f\x89E\xe8\x83E\xec\x02\x0f\xbfE\xe8\x85\xc0\x0f"
    + b"\x8c\n\x00\x00\x00\xe9\x9a\x01\x00\x00\xe9h\x00\x00\x00\xf6E\xe9@\x0f\x84\x05"
)
LINE_MISMATCH_EXAMPLE_RECOMP = (
    b"+\xc8If\x89M\xfc\x8bE\xf4f\x8b\x00f\x89E\xf0\x83E\xf4\x02\x0f\xbfE\xf0\x85\xc0\x0f\x8d~\x00\x00\x00\x0f\xbfE\xf0\xf6\xc4@\x0f\x84\x13\x00\x00\x00\x0f\xbfE\xfc\x0f\xbf"
    + b"M\xf0\x03\xc1f\x89E\xfc\xe9a\x01\x00\x00\x8bE\xf0P\x8bE\xfcP\x8b"
)


def test_example_where_diff_mismatches_lines(
    db: EntityDb, report: ReccmpReportProtocol
):
    """The text based diff sometimes misjudges which parts correspond when there are a lot of differences. This tests captures one such case."""

    diffreport = compare_functions(
        db, LINE_MISMATCH_EXAMPLE_ORIG, LINE_MISMATCH_EXAMPLE_RECOMP, report
    )

    assert diffreport.ratio < 1.0
    assert diffreport.udiff == [
        (
            "@@ -0x200,19 +0x400,22 @@",
            [
                {
                    "both": [
                        ("0x200", "sub ecx, eax", "0x400"),
                        ("0x202", "dec ecx", "0x402"),
                    ]
                },
                {
                    "orig": [
                        ("0x203", "mov word ptr [ebp - 0x28], cx"),
                        ("0x207", "jmp 0x1d1"),
                        ("0x20c", "jmp 0xe"),
                        ("0x211", "movsx eax, word ptr [ebp - 0x18]"),
                        ("0x215", "movsx ecx, word ptr [ebp - 0x28]"),
                    ],
                    "recomp": [
                        ("0x403", "mov word ptr [ebp - 4], cx"),
                        ("0x407", "mov eax, dword ptr [ebp - 0xc]"),
                        ("0x40a", "mov ax, word ptr [eax]"),
                        ("0x40d", "mov word ptr [ebp - 0x10], ax"),
                        ("0x411", "add dword ptr [ebp - 0xc], 2"),
                        ("0x415", "movsx eax, word ptr [ebp - 0x10]"),
                        ("0x419", "test eax, eax"),
                        ("0x41b", "jge 0x7e"),
                        ("0x421", "movsx eax, word ptr [ebp - 0x10]"),
                        ("0x425", "test ah, 0x40"),
                        ("0x428", "je 0x13"),
                        ("0x42e", "movsx eax, word ptr [ebp - 4]"),
                        ("0x432", "movsx ecx, word ptr [ebp - 0x10]"),
                    ],
                },
                {
                    "both": [
                        ("0x219", "add eax, ecx", "0x436"),
                    ]
                },
                {
                    "orig": [
                        ("0x21b", "mov word ptr [ebp - 0x28], ax"),
                        ("0x21f", "mov eax, dword ptr [ebp - 0x14]"),
                        ("0x222", "mov ax, word ptr [eax]"),
                        ("0x225", "mov word ptr [ebp - 0x18], ax"),
                        ("0x229", "add dword ptr [ebp - 0x14], 2"),
                        ("0x22d", "movsx eax, word ptr [ebp - 0x18]"),
                        ("0x231", "test eax, eax"),
                        ("0x233", "jl 0xa"),
                        ("0x239", "jmp 0x19a"),
                        ("0x23e", "jmp 0x68"),
                        ("0x243", "test byte ptr [ebp - 0x17], 0x40"),
                    ],
                    "recomp": [
                        ("0x438", "mov word ptr [ebp - 4], ax"),
                        ("0x43c", "jmp 0x161"),
                        ("0x441", "mov eax, dword ptr [ebp - 0x10]"),
                        ("0x444", "push eax"),
                        ("0x445", "mov eax, dword ptr [ebp - 4]"),
                        ("0x448", "push eax"),
                    ],
                },
            ],
        )
    ]


def test_impact_of_line_annotation(db: EntityDb, report: ReccmpReportProtocol):
    """When text based diff misjudges which parts correspond, a `// LINE` annotation may help. This test uses the same binary, but with such an annotation."""

    add_line_annotation(db, 31, 7)

    diffreport = compare_functions(
        db, LINE_MISMATCH_EXAMPLE_ORIG, LINE_MISMATCH_EXAMPLE_RECOMP, report
    )

    assert diffreport.udiff == [
        (
            "@@ -0x200,9 +0x400,3 @@",
            [
                {
                    "both": [
                        ("0x200", "sub ecx, eax", "0x400"),
                        ("0x202", "dec ecx", "0x402"),
                    ]
                },
                {
                    "orig": [
                        ("0x203", "mov word ptr [ebp - 0x28], cx"),
                        ("0x207", "jmp 0x1d1"),
                        ("0x20c", "jmp cppfile.cpp:384 (LINE)"),
                        ("0x211", "movsx eax, word ptr [ebp - 0x18]"),
                        ("0x215", "movsx ecx, word ptr [ebp - 0x28]"),
                        ("0x219", "add eax, ecx"),
                        ("0x21b", "mov word ptr [ebp - 0x28], ax"),
                    ],
                    "recomp": [
                        ("0x403", "mov word ptr [ebp - 4], cx"),
                    ],
                },
            ],
        ),
        (
            "@@ -0x21f,1 +0x407,1 @@",
            [
                {
                    "orig": [
                        ("0x21f", "mov eax, dword ptr [ebp - 0x14]"),
                    ],
                    "recomp": [
                        ("0x407", "mov eax, dword ptr [ebp - 0xc]"),
                    ],
                }
            ],
        ),
        (
            "@@ -0x222,9 +0x40a,18 @@",
            [
                {
                    "both": [
                        ("0x222", "mov ax, word ptr [eax]", "0x40a"),
                    ]
                },
                {
                    # Note how these blocks correspond, but but without the // LINE annotation they do not
                    "orig": [
                        ("0x225", "mov word ptr [ebp - 0x18], ax"),
                        ("0x229", "add dword ptr [ebp - 0x14], 2"),
                        ("0x22d", "movsx eax, word ptr [ebp - 0x18]"),
                    ],
                    "recomp": [
                        ("0x40d", "mov word ptr [ebp - 0x10], ax"),
                        ("0x411", "add dword ptr [ebp - 0xc], 2"),
                        ("0x415", "movsx eax, word ptr [ebp - 0x10]"),
                    ],
                },
                {
                    "both": [
                        ("0x231", "test eax, eax", "0x419"),
                    ]
                },
                {
                    "orig": [
                        ("0x233", "jl 0xa"),
                        ("0x239", "jmp 0x19a"),
                        ("0x23e", "jmp 0x68"),
                        ("0x243", "test byte ptr [ebp - 0x17], 0x40"),
                    ],
                    "recomp": [
                        ("0x41b", "jge 0x7e"),
                        ("0x421", "movsx eax, word ptr [ebp - 0x10]"),
                        ("0x425", "test ah, 0x40"),
                        ("0x428", "je 0x13"),
                        ("0x42e", "movsx eax, word ptr [ebp - 4]"),
                        ("0x432", "movsx ecx, word ptr [ebp - 0x10]"),
                        ("0x436", "add eax, ecx"),
                        ("0x438", "mov word ptr [ebp - 4], ax"),
                        ("0x43c", "jmp 0x161"),
                        ("0x441", "mov eax, dword ptr [ebp - 0x10]"),
                        ("0x444", "push eax"),
                        ("0x445", "mov eax, dword ptr [ebp - 4]"),
                        ("0x448", "push eax"),
                    ],
                },
            ],
        ),
    ]


def test_line_annotation_invalid_orig_address(db: EntityDb, report):
    # based on BETA10 0x1013e61d
    code = b"U\x8b\xec\x83\xec,SVWf\xc7E\xf8\x00\x00f\xc7E\xf0\x00\x00\x8bE\x14"

    add_line_annotation(db, 2, 0)

    compare_functions(db, code, code, report)

    report.assert_called_with(
        ReccmpEvent.NO_MATCH,
        ORIG_GLOBAL_OFFSET + 2,
        "Found no code line corresponding to this original address",
    )


def test_line_annotation_invalid_recomp_address(db: EntityDb, report):
    code = b"U\x8b\xec\x83\xec,SVWf\xc7E\xf8\x00\x00f\xc7E\xf0\x00\x00\x8bE\x14"

    add_line_annotation(db, 1, 2)

    compare_functions(db, code, code, report)

    report.assert_called_with(
        ReccmpEvent.NO_MATCH,
        ORIG_GLOBAL_OFFSET + 1,
        "Found no code line corresponding to recomp address 0x402. Recompilation may fix this problem.",
    )


def test_line_annotation_wrong_order(db: EntityDb, report):
    code = b"U\x8b\xec\x83\xec,SVWf\xc7E\xf8\x00\x00f\xc7E\xf0\x00\x00\x8bE\x14"

    add_line_annotation(db, 0, 3)
    add_line_annotation(db, 3, 0)

    compare_functions(db, code, code, report)

    report.assert_called_with(
        ReccmpEvent.WRONG_ORDER,
        ORIG_GLOBAL_OFFSET + 3,
        "Line annotation 'cppfile.cpp:384' is out of order relative to other line annotations.",
    )


def test_no_assembly_generated(db: EntityDb, report):
    # `capstone` produces no code for these instructions.
    # This test checks for correct edge case handling (e.g. no implicit assumptions that there will always be some assembly)
    code = b"\xcc"
    recm = b"\xcd"

    diffreport = compare_functions(db, code, recm, report)

    assert diffreport.ratio == 1.0


def test_displacement_without_match(db: EntityDb, report: ReccmpReportProtocol):
    orig = b"\x89\x3c\x85\xa8\x15\xc8\x00"
    recm = b"\x89\x3c\x85\xa8\x15\xd0\x00"

    diffreport = compare_functions(db, orig, recm, report)

    assert diffreport.ratio < 1.0

    assert diffreport.udiff == [
        (
            "@@ -0x200,1 +0x400,1 @@",
            [
                {
                    "orig": [("0x200", "mov dword ptr [eax*4 + 0xc815a8], edi")],
                    "recomp": [("0x400", "mov dword ptr [eax*4 + 0xd015a8], edi")],
                }
            ],
        )
    ]


def test_displacement_with_match(db: EntityDb, report: ReccmpReportProtocol):
    # mov dword ptr [eax*4 + 0xc815a8], edi
    orig = b"\x89\x3c\x85\xa8\x15\xc8\x00"
    recm = b"\x89\x3c\x85\xa8\x15\xd0\x00"

    orig_addr = 0xC815A8
    recomp_addr = 0xD015A8
    db.set_recomp_symbol(recomp_addr, name="some_global")
    db.set_pair(orig_addr, recomp_addr, EntityType.DATA)

    diffreport = compare_functions(db, orig, recm, report)

    assert diffreport.ratio == 1.0


def test_matching_jump_table(db: EntityDb, report: ReccmpReportProtocol):
    """Jump tables of functions matching relative to the different offsets of the functions"""
    orig = b"\xff\x24\x85\x07\x02\x00\x00\x33\x04\x00\x00\x43\x04\x00\x00"
    recm = b"\xff\x24\x85\x07\x04\x00\x00\x33\x06\x00\x00\x43\x06\x00\x00"

    is_relocated_addr = Mock(return_value=True)
    # is_relocated_addr = None
    diffreport = compare_functions(db, orig, recm, report, is_relocated_addr)

    assert diffreport.ratio == 1.0
    assert diffreport.is_effective_match is False


def test_jump_table_wrong_order(db: EntityDb, report: ReccmpReportProtocol):
    """
    Jump tables with the correct entries in the wrong order.
    In particular, this must not become an accidental effective match.
    """
    orig = b"\xff\x24\x85\x07\x02\x00\x00\x33\x04\x00\x00\x43\x04\x00\x00"
    recm = b"\xff\x24\x85\x07\x04\x00\x00\x43\x06\x00\x00\x33\x06\x00\x00"

    # Required to get an `<OFFSET1> into the jump instruction`
    is_relocated_addr = Mock(return_value=True)
    diffreport = compare_functions(db, orig, recm, report, is_relocated_addr)

    assert diffreport.ratio < 1.0
    assert diffreport.is_effective_match is False

    assert diffreport.udiff == [
        (
            "@@ -,4 +,4 @@",
            [
                {
                    "both": [
                        ("0x200", "jmp dword ptr [eax*4 + <OFFSET1>]", "0x400"),
                        ("", "Jump table:", ""),
                    ],
                },
                {"orig": [], "recomp": [("0x407", "start + 0x243")]},
                {"both": [("0x207", "start + 0x233", "0x40b")]},
                {"orig": [("0x20b", "start + 0x243")], "recomp": []},
            ],
        )
    ]
