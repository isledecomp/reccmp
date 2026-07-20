"""For demangling a subset of MSVC mangled symbols.
Some unofficial information about the mangling scheme is here:
https://en.wikiversity.org/wiki/Visual_C%2B%2B_name_mangling
"""

import re
from typing import NamedTuple
from pydemumble import demangle as _demangle  # type: ignore


def msvc_demangle(symbol: str) -> str:
    """Wrapper for demumbler. Converts MSVC C++ symbol to a name
    more similar to what appears in the code.
    If no conversion is possible, return empty string."""
    return _demangle(symbol) or ""


class InvalidEncodedNumberError(Exception):
    pass


_encoded_number_translate = str.maketrans("ABCDEFGHIJKLMNOP", "0123456789ABCDEF")


def parse_encoded_number(string: str) -> int:
    # TODO: assert string ends in "@"?
    if string.endswith("@"):
        string = string[:-1]

    try:
        return int(string.translate(_encoded_number_translate), 16)
    except ValueError as e:
        raise InvalidEncodedNumberError(string) from e


string_const_regex = re.compile(
    r"\?\?_C@\_(?P<is_utf16>[0-1])(?P<len>\d|[A-P]+@)(?P<hash>\w+)@(?P<value>.+)@"
)


class StringConstInfo(NamedTuple):
    len: int
    is_utf16: bool


def demangle_string_const(symbol: str) -> StringConstInfo | None:
    """Don't bother to decode the string text from the symbol.
    We can just read it from the binary once we have the length."""
    match = string_const_regex.match(symbol)
    if match is None:
        return None

    try:
        strlen = (
            parse_encoded_number(match.group("len"))
            if "@" in match.group("len")
            else int(match.group("len"))
        )
    except (ValueError, InvalidEncodedNumberError):
        return None

    is_utf16 = match.group("is_utf16") == "1"
    return StringConstInfo(len=strlen, is_utf16=is_utf16)


def get_vtordisp_name(symbol: str) -> str | None:
    # pylint: disable=c-extension-no-member
    """For adjuster thunk functions, the PDB will sometimes use a name
    that contains "vtordisp" but often will just reuse the name of the
    function being thunked. We want to use the vtordisp name if possible."""
    name = msvc_demangle(symbol)
    if not name:
        return None

    if "`vtordisp" not in name:
        return None

    # Now we remove the parts of the friendly name that we don't need
    try:
        # Assuming this is the last of the function prefixes
        thiscall_idx = name.index("__thiscall")
        # To match the end of the `vtordisp{x,y}' string
        end_idx = name.index("}'")
        return name[thiscall_idx + 11 : end_idx + 2]
    except ValueError:
        return name


def get_function_arg_string(symbol: str) -> str | None:
    # pylint: disable=c-extension-no-member
    """Demangle the given symbol and return its parameters.
    We can use this to distinguish functions with the same name."""
    raw = msvc_demangle(symbol)
    if not raw:
        return None

    try:
        # Just get what's in the parens
        return raw[raw.index("(") : raw.rindex(")") + 1]
    except ValueError:
        return None


def demangle_vtable(symbol: str) -> str:
    # pylint: disable=c-extension-no-member
    """Get the class name referenced in the vtable symbol."""
    raw = msvc_demangle(symbol)

    if not raw:
        pass  # TODO: This shouldn't happen if MSVC behaves

    # Remove storage class and other stuff we don't care about
    return (
        raw.replace("<class ", "<")
        .replace("<struct ", "<")
        .replace("const ", "")
        .replace("volatile ", "")
    )


def demangle_vtable_ourselves(symbol: str) -> str:
    """Parked implementation of MSVC symbol demangling.
    We only use this for vtables and it works okay with the simple cases or
    templates that refer to other classes/structs. Some namespace support.
    Does not support backrefs, primitive types, or vtables with
    virtual inheritance."""

    # Seek ahead 4 chars to strip off "??_7" prefix
    t = symbol[4:].split("@")
    # "?$" indicates a template class
    if t[0].startswith("?$"):
        class_name = t[0][2:]
        # PA = Pointer/reference
        # V or U = class or struct
        if t[1].startswith("PA"):
            generic = f"{t[1][3:]} *"
        else:
            generic = t[1][1:]

        return f"{class_name}<{generic}>::`vftable'"

    # If we have two classes listed, it is a namespace hierarchy.
    # @@6B@ is a common generic suffix for these vtable symbols.
    if t[1] != "" and t[1] != "6B":
        return t[1] + "::" + t[0] + "::`vftable'"

    return t[0] + "::`vftable'"


class FunctionSignatureInfo(NamedTuple):
    """Calling convention and return-value register footprint recovered
    from a decorated name. Either field may be unknown."""

    return_kind: str  # void / i8 / i16 / i32 / i64 / float / unknown
    convention: str | None  # cdecl / stdcall / thiscall / fastcall / None


_MANGLED_CONVENTIONS = {
    "A": "cdecl",
    "B": "cdecl",
    "E": "thiscall",
    "F": "thiscall",
    "G": "stdcall",
    "H": "stdcall",
    "I": "fastcall",
    "J": "fastcall",
}

# Member-function access codes: does the calling convention follow
# directly (static) or after a cv-qualifier character?
_MEMBER_STATIC = set("CDKLST")
_MEMBER_NONSTATIC = set("ABEFIJMNQRUV")

_MANGLED_RETURN_KINDS = {
    "X": "void",
    "C": "i8",
    "D": "i8",
    "E": "i8",
    "F": "i16",
    "G": "i16",
    "H": "i32",
    "I": "i32",
    "J": "i32",
    "K": "i32",
    "M": "float",
    "N": "float",
    "O": "float",
}


def _mangled_return_kind(code: str) -> str:
    if not code:
        return "unknown"
    if code[0] == "_":
        return {"_N": "i8", "_J": "i64", "_K": "i64", "_W": "i16"}.get(
            code[:2], "unknown"
        )
    if code[0] in "PQRSA":
        # Pointers and references return in eax.
        return "i32"
    if code.startswith("W4"):
        # Enumerations have a 4-byte underlying type.
        return "i32"
    return _MANGLED_RETURN_KINDS.get(code[0], "unknown")


def parse_function_signature(symbol: str) -> FunctionSignatureInfo:
    """Recover the calling convention and return kind from a decorated
    function name. Anything unrecognized degrades to unknown."""
    # pylint: disable=too-many-return-statements
    unknown = FunctionSignatureInfo("unknown", None)
    if not symbol:
        return unknown

    if not symbol.startswith("?"):
        # C-style decoration: _name (cdecl), _name@N (stdcall), @name@N
        # (fastcall). No return-type information.
        if symbol.startswith("_"):
            if "@" in symbol[1:]:
                return FunctionSignatureInfo("unknown", "stdcall")
            return FunctionSignatureInfo("unknown", "cdecl")
        if symbol.startswith("@") and "@" in symbol[1:]:
            return FunctionSignatureInfo("unknown", "fastcall")
        return unknown

    if "?$" in symbol:
        # Template arguments embed "@@", which breaks the simple split.
        return unknown

    _, sep, code = symbol.partition("@@")
    if not sep or not code:
        return unknown

    if code[0] == "Y":
        # Global function: Y <convention> <return type> <args> Z
        if len(code) < 3:
            return unknown
        convention = _MANGLED_CONVENTIONS.get(code[1])
        return FunctionSignatureInfo(_mangled_return_kind(code[2:]), convention)

    if code[0] in _MEMBER_STATIC:
        if len(code) < 3:
            return unknown
        convention = _MANGLED_CONVENTIONS.get(code[1])
        return FunctionSignatureInfo(_mangled_return_kind(code[2:]), convention)

    if code[0] in _MEMBER_NONSTATIC:
        # Access code, then a cv-qualifier (A-D), then the convention.
        if len(code) < 4 or code[1] not in "ABCD":
            return unknown
        convention = _MANGLED_CONVENTIONS.get(code[2])
        rest = code[3:]
        if rest.startswith("@"):
            # Constructors and destructors have no return type; MSVC
            # returns `this` from a constructor, so leave it unknown.
            return FunctionSignatureInfo("unknown", convention)
        return FunctionSignatureInfo(_mangled_return_kind(rest), convention)

    return unknown
