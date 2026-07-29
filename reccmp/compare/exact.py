"""Relocation-masked exact comparison for function bodies in COFF objects."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

RELOCATION_TYPES = frozenset({0x06, 0x07, 0x14})


@dataclass(frozen=True)
class CoffFunction:
    """One external i386 COFF function and its contributing relocations."""

    name: str
    body: bytes
    relocation_offsets: tuple[int, ...]
    source_object: str = ""

    @property
    def masked_body(self) -> bytes:
        return mask_relocations(self.body, self.relocation_offsets)


@dataclass(frozen=True)
class ExactComparison:
    """A recomputed exact-body verdict; no persistent digest is involved."""

    status: str
    exact_mode: str
    original_size: int
    recompiled_size: int
    stable_bytes: int

    @property
    def exact(self) -> bool:
        return self.status == "exact"


def coff_name(data: bytes, raw: bytes, string_table: int) -> str:
    """Decode an inline or string-table COFF name."""
    if raw[:4] == b"\0\0\0\0":
        offset = struct.unpack_from("<I", raw, 4)[0]
        return data[string_table + offset :].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        )
    return raw[:8].rstrip(b"\0").decode("utf-8", errors="replace")


def _source_name(name: str) -> str:
    value = name.removeprefix("_")
    if "@" in value and value.rsplit("@", 1)[-1].isdigit():
        value = value.rsplit("@", 1)[0]
    return value


def parse_coff_functions(path: Path) -> list[CoffFunction]:  # pylint: disable=too-many-locals
    """Parse external function COMDATs from an i386 COFF object.

    A function body stops at the next external function symbol or the end of
    its section.  Alignment padding is removed, while associated jump-table
    bytes remain available for callers that know the PDB function extent.
    """

    data = path.read_bytes()
    if len(data) < 20:
        raise RuntimeError(f"COFF object is too short: {path}")
    machine, section_count, _timestamp, symbol_table, symbol_count, optional_size, _flags = (
        struct.unpack_from("<HHIIIHH", data, 0)
    )
    if machine != 0x14C or optional_size != 0:
        raise RuntimeError(f"not an i386 COFF object: {path}")
    string_table = symbol_table + symbol_count * 18
    sections: dict[int, dict[str, Any]] = {}
    section_offset = 20
    for index in range(1, section_count + 1):
        header = data[section_offset : section_offset + 40]
        name = coff_name(data, header[:8], string_table)
        size, raw_offset, relocation_offset, _lines, relocation_count, _line_count, _attrs = (
            struct.unpack_from("<IIIIHHI", header, 16)
        )
        sections[index] = {
            "name": name,
            "data": data[raw_offset : raw_offset + size] if raw_offset else b"",
            "relocations": [
                struct.unpack_from("<IIH", data, relocation_offset + position * 10)
                for position in range(relocation_count)
            ],
        }
        section_offset += 40

    symbols: list[tuple[str, int, int, int, int]] = []
    symbol_index = 0
    while symbol_index < symbol_count:
        raw = data[symbol_table + symbol_index * 18 : symbol_table + symbol_index * 18 + 18]
        name = coff_name(data, raw, string_table)
        value, section, symbol_type, storage, auxiliary_count = struct.unpack_from(
            "<IhHBB", raw, 8
        )
        symbols.append((name, value, section, symbol_type, storage))
        symbol_index += 1 + auxiliary_count

    functions: list[CoffFunction] = []
    by_section: dict[int, list[tuple[str, int]]] = {}
    for name, value, section, symbol_type, storage in symbols:
        if (
            section > 0
            and storage == 2
            and symbol_type == 0x20
            and sections[section]["name"].startswith(".text")
        ):
            by_section.setdefault(section, []).append((name, value))
    for section_index, entries in sorted(by_section.items()):
        section = sections[section_index]
        entries.sort(key=lambda item: (item[1], item[0]))
        for position, (name, start) in enumerate(entries):
            end = entries[position + 1][1] if position + 1 < len(entries) else len(section["data"])
            body = section["data"][start:end].rstrip(b"\x90")
            if not body:
                continue
            offsets = tuple(
                sorted(
                    address - start
                    for address, _symbol, kind in section["relocations"]
                    if kind in RELOCATION_TYPES and start <= address <= end - 4
                )
            )
            functions.append(
                CoffFunction(_source_name(name), body, offsets, source_object=str(path))
            )
    if not functions:
        raise RuntimeError(f"COFF object exposes no external .text functions: {path}")
    return sorted(functions, key=lambda item: item.name.casefold())


def mask_relocations(body: bytes, offsets: Iterable[int]) -> bytes:
    masked = bytearray(body)
    for offset in offsets:
        if 0 <= offset and offset + 4 <= len(masked):
            masked[offset : offset + 4] = b"\0\0\0\0"
    return bytes(masked)


def stable_ranges(length: int, offsets: Iterable[int]) -> list[tuple[int, int]]:
    holes = [False] * length
    for offset in offsets:
        if offset < 0 or offset + 4 > length:
            continue
        for index in range(offset, offset + 4):
            holes[index] = True
    ranges: list[tuple[int, int]] = []
    start = None
    for index, hole in enumerate([*holes, True]):
        if not hole and start is None:
            start = index
        elif hole and start is not None:
            ranges.append((start, index))
            start = None
    return ranges


def compare_relocation_masked(
    original: bytes,
    recompiled: bytes,
    *,
    original_relocations: Iterable[int] = (),
    recompiled_relocations: Iterable[int] = (),
    size: int | None = None,
) -> ExactComparison:
    """Compare current bodies after masking all relocatable four-byte operands."""

    original_size = len(original) if size is None else size
    recompiled_size = len(recompiled)
    offsets = tuple(sorted(set(original_relocations) | set(recompiled_relocations)))
    comparable = original[:original_size]
    candidate = recompiled[:original_size]
    ranges = stable_ranges(original_size, offsets)
    exact = recompiled_size >= original_size and all(
        comparable[start:end] == candidate[start:end] for start, end in ranges
    )
    return ExactComparison(
        status="exact" if exact else "different",
        exact_mode="relocation-masked-object",
        original_size=original_size,
        recompiled_size=recompiled_size,
        stable_bytes=sum(end - start for start, end in ranges),
    )
