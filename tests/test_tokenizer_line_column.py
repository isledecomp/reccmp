from textwrap import dedent
from reccmp.parser.tokenizer import (
    get_newlines_from_text,
    get_line_column_pos,
)


def test_line_col_conversion():
    """Should accurately convert the absolute position into 1-based line and column numbers."""
    code = dedent("""\
        // Example file

        // Test
    """)
    newlines = get_newlines_from_text(code)

    assert get_line_column_pos(newlines, 0) == (1, 1)
    assert get_line_column_pos(newlines, 1) == (1, 2)
    assert get_line_column_pos(newlines, 15) == (1, 16)
    assert get_line_column_pos(newlines, 16) == (2, 1)
    assert get_line_column_pos(newlines, 17) == (3, 1)
    assert get_line_column_pos(newlines, 23) == (3, 7)
    assert get_line_column_pos(newlines, 24) == (3, 8)

    # The conversion is simple arithmetic: there is currently no range check.
    assert get_line_column_pos(newlines, len(code)) == (4, 1)
