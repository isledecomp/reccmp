import re

r_likely_string = re.compile(r"[\t\r\n\x20-\x7f][\t\r\n\x20-\x7f\xa0-\xff]*")
r_likely_widechar = re.compile(r"[\t\r\n\x20-\x7f][\t\r\n\x20-\xffff]*")


def is_likely_latin1(string) -> bool:
    """Heuristic to eliminate data streams that are not real strings.
    We exclude bytes not in the Latin1 (ISO/IEC 8859-1) character set
    and also assume the string begins with an ASCII character."""
    return r_likely_string.fullmatch(string) is not None


def is_likely_widechar(string: str) -> bool:
    """Heuristic for UTF-16LE strings recovered from PE relocation targets.

    Require a printable ASCII start (same as Latin1 strings) so random
    word-aligned data is not treated as a wide string. Empty strings are
    accepted so MSVC NUL pooling can still form a WIDECHAR entity."""
    if string == "":
        return True
    return r_likely_widechar.fullmatch(string) is not None
