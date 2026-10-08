# C++ Parser utility functions and data structures
import re
from typing import NamedTuple

# The goal here is to just read whatever is on the next line, so some
# flexibility in the formatting seems OK
templateCommentRegex = re.compile(r"\s*//\s*(.*)")

# To remove any comment (//) or block comment (/*) and its leading spaces
# from the end of a code line
trailingCommentRegex = re.compile(r"(\s*(?://|/\*).*)$")

# Get string contents, ignore escape characters that might interfere
doubleQuoteRegex = re.compile(r'(L)?"((?:[^"\\]|\\.)*)"')

# C string escape sequences that we can unescape.
stringEscapeRegex = re.compile(
    r"\\(?:(?P<octal>[0-7]{1,3})|x(?P<hex>[0-9a-fA-F]+)|(?P<char>.))", flags=re.S
)

escape_sequences = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
}


def get_synthetic_name(line: str) -> str | None:
    """Synthetic names appear on a single line comment on the line after the marker.
    If that's not what we have, return None"""
    template_match = templateCommentRegex.match(line)

    if template_match is not None:
        return template_match.group(1).strip()

    return None


def remove_trailing_comment(line: str) -> str:
    return trailingCommentRegex.sub("", line)


def is_blank_or_comment(line: str) -> bool:
    """Helper to read ahead after the offset comment is matched.
    There could be blank lines or other comments before the
    function signature, and we want to skip those."""
    line_strip = line.strip()
    return (
        len(line_strip) == 0
        or line_strip.startswith("//")
        or line_strip.startswith("/*")
        or line_strip.endswith("*/")
    )


template_regex = re.compile(r"<(?P<type>[\w]+)\s*(?P<asterisks>\*+)?\s*>")


class_decl_regex = re.compile(
    r"\s*(?:\/\/)?\s*(?:class|struct) ((?:\w+(?:<.+>)?(?:::)?)+)"
)


def template_replace(match: re.Match) -> str:
    type_name, asterisks = match.groups()
    if asterisks is None:
        return f"<{type_name}>"

    return f"<{type_name} {asterisks}>"


def fix_template_type(class_name: str) -> str:
    """For template classes, we should reformat the class name so it matches
    the output from cvdump: one space between the template type and any asterisks
    if it is a pointer type."""
    if "<" not in class_name:
        return class_name

    return template_regex.sub(template_replace, class_name)


def get_class_name(line: str) -> str | None:
    """For VTABLE markers, extract the class name from the code line or comment
    where it appears."""

    match = class_decl_regex.match(line)
    if match is not None:
        return fix_template_type(match.group(1))

    return None


global_regex = re.compile(
    r"""
    (?P<name>(?:\w+::)*\w+)       # Any identifier with 0-N namespace qualifiers
    (?:                           # Suffix options:
        \(\w|                     # - Open paren: call constructor
        \)\(|                     # - Close paren, open paren: function pointer variable
        \[.*|                     # - Open bracket: array with or without size
        \s*=.*|                   # - Direct assignment
        ;                         # - Not initialized
    )
""",
    flags=re.X,
)


def get_variable_name(line: str) -> str | None:
    """Grab the name of the variable annotated with the GLOBAL marker."""

    if (match := global_regex.search(line)) is not None:
        return match.group("name")

    return None


class ParserCodeString(NamedTuple):
    text: str
    is_widechar: bool


def unescape_replace(match: re.Match) -> str:
    octal, hex_, char = match.groups()

    if octal is not None:
        return chr(int(octal, 8))

    if hex_ is not None:
        try:
            value = int(hex_, 16)
            if value > 0xFFFF:
                # Value exceeds wchar_t
                return match.group(0)

            return chr(value)
        except ValueError:
            return match.group(0)

    # Replace known sequences with the escaped character.
    # In all other cases, drop the slash.
    return escape_sequences.get(char, char)


def get_string_contents(line: str) -> ParserCodeString | None:
    """Return the string contents from the given token after resolving escape sequences.
    Widechar strings are indicated by the 'L' prefix in the token. We take some shortcuts
    for convenience: hex sequences are evaluated as widechar even for ASCII strings.
    The intent is to represent the string text well enough for our purposes.
    The user is expected to provide valid input that the compiler will accept."""
    if (match := doubleQuoteRegex.search(line)) is None:
        return None

    return ParserCodeString(
        text=stringEscapeRegex.sub(unescape_replace, match.group(2)),
        is_widechar=match.group(1) is not None,
    )
