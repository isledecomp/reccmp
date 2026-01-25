from difflib import SequenceMatcher

import pytest
from reccmp.decomp.compare.pinned_sequences import SequenceMatcherWithPins


def test_equal_sequences_matching_pin():
    """Pins on equal sequences should only have 'equal' opcodes,
    and the opcodes should be split at the match point"""
    a = b = ["a", "b", "c", "d", "e", "f"]
    pins = [(3, 3)]
    diff = SequenceMatcherWithPins(a, b, pins)

    assert diff.get_opcodes() == [("equal", 0, 3, 0, 3), ("equal", 3, 6, 3, 6)]
    assert list(diff.get_grouped_opcodes()) == [
        [("equal", 0, 3, 0, 3), ("equal", 3, 6, 3, 6)]
    ]


def test_equal_sequences_mismatching_pin():
    """Pinning the wrong lines should produce non-trivial opcodes"""
    a = b = ["a", "b", "c", "d", "e", "f"]
    pins = [(3, 2)]
    diff = SequenceMatcherWithPins(a, b, pins)

    assert diff.get_opcodes() == [
        ("equal", 0, 2, 0, 2),
        ("delete", 2, 3, 2, 2),
        ("insert", 3, 3, 2, 3),
        ("equal", 3, 6, 3, 6),
    ]
    assert list(diff.get_grouped_opcodes()) == [
        [
            ("equal", 0, 2, 0, 2),
            ("delete", 2, 3, 2, 2),
            ("insert", 3, 3, 2, 3),
            ("equal", 3, 6, 3, 6),
        ]
    ]


@pytest.mark.parametrize(
    "a,b",
    [
        (["a", "b", "c"], ["a", "b", "d"]),
        ([], []),
        ([], ["a"]),
        (["a"], []),
        (["a", "b", "c", "d", "e", "f"], ["a", "b", "c", "d", "g", "f"]),
        (["a", "b"], ["c", "d"]),
    ],
)
def test_consistency_with_sequencematcher_in_absence_of_pins(a, b):
    diff_old = SequenceMatcher(a=a, b=b)
    diff_new = SequenceMatcherWithPins(a, b, [])

    assert diff_new.get_opcodes() == diff_old.get_opcodes()
    assert list(diff_new.get_grouped_opcodes()) == list(diff_old.get_grouped_opcodes())


def test_groups_with_pins():
    a = ["0", "a", "b", "c", "d", "e", "f", "d2", "e2", "f2", "i", "j"]
    b = ["1", "a", "b", "c", "d", "e", "f", "d2", "e2", "f2", "h", "j"]
    pins = [(8, 8)]

    diff_without_pins = SequenceMatcherWithPins(a, b, [])
    diff_with_pins = SequenceMatcherWithPins(a, b, pins)

    assert diff_without_pins.get_opcodes() == [
        ("replace", 0, 1, 0, 1),
        ("equal", 1, 10, 1, 10),
        ("replace", 10, 11, 10, 11),
        ("equal", 11, 12, 11, 12),
    ]
    assert list(diff_without_pins.get_grouped_opcodes()) == [
        [("replace", 0, 1, 0, 1), ("equal", 1, 4, 1, 4)],
        [
            ("equal", 7, 10, 7, 10),
            ("replace", 10, 11, 10, 11),
            ("equal", 11, 12, 11, 12),
        ],
    ]

    assert list(diff_with_pins.get_opcodes()) == [
        ("replace", 0, 1, 0, 1),
        ("equal", 1, 8, 1, 8),
        ("equal", 8, 10, 8, 10),
        ("replace", 10, 11, 10, 11),
        ("equal", 11, 12, 11, 12),
    ]
    assert list(diff_with_pins.get_grouped_opcodes()) == [
        [("replace", 0, 1, 0, 1), ("equal", 1, 4, 1, 4)],
        [
            ("equal", 5, 8, 5, 8),
            # The groups are always interrupted at the pins, which is desired.
            # This causes the pins to never be part of a skipped section.
            ("equal", 8, 10, 8, 10),
            ("replace", 10, 11, 10, 11),
            ("equal", 11, 12, 11, 12),
        ],
    ]


def test_degenerate_pins():
    """
    Pins appearing multiple times or at the beginning and end should not affect the output.
    """
    a = b = ["a", "b", "c", "d", "e", "f"]
    pins = [(0, 0), (3, 3), (3, 3), (6, 6)]
    diff = SequenceMatcherWithPins(a, b, pins)

    assert diff.get_opcodes() == [("equal", 0, 3, 0, 3), ("equal", 3, 6, 3, 6)]
    assert list(diff.get_grouped_opcodes()) == [
        [("equal", 0, 3, 0, 3), ("equal", 3, 6, 3, 6)]
    ]


def test_pins_out_of_range():
    a = b = ["a", "b", "c", "d", "e", "f"]
    pins = [(5, 8)]
    diff = SequenceMatcherWithPins(a, b, pins)

    assert diff.get_opcodes() == [("equal", 0, 6, 0, 6)]
    assert not list(diff.get_grouped_opcodes())


def test_non_monotonous_pins():
    a = b = ["a", "b", "c", "d", "e", "f"]
    pins = [(3, 3), (4, 2)]

    with pytest.raises(ValueError):
        SequenceMatcherWithPins(a, b, pins)
