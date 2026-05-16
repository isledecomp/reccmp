"""
Based on the following resources:
- https://github.com/bitwiseworks/os2tk45/blob/master/h/newexe.h
- https://github.com/qb40/exe-format/blob/master/README.txt
"""

import dataclasses
import struct
from pathlib import Path
from types import MappingProxyType
from typing import Iterator, Mapping
from enum import Enum, IntEnum, IntFlag
from typing_extensions import Buffer

from reccmp.types import ConcreteBuffer
from .exceptions import (
    InvalidVirtualAddressError,
    SectionNotFoundError,
)
from .image import Image, ImageImport, ImageSection, ImageRegion
from .mz import ImageDosHeader


def pascal_string(data: ConcreteBuffer, offset: int = 0) -> str:
    strlen = data[offset]
    return bytes(data[offset + 1 : offset + strlen + 1]).decode("ascii")


class NESegmentFlags(IntFlag):
    # pylint: disable=implicit-flag-alias
    NESOLO = 0x0001  # Solo data
    NEINST = 0x0002  # Instance data
    NEPPLI = 0x0004  # Per-Process Library Initialization
    NEPROT = 0x0008  # Runs in protected mode only
    NEI086 = 0x0010  # 8086 instructions
    NEI286 = 0x0020  # 286 instructions
    NEI386 = 0x0040  # 386 instructions
    NEFLTP = 0x0080  # Floating-point instructions
    NENOTWINCOMPAT = 0x0100  # Not compatible with P.M. Windowing
    NEWINCOMPAT = 0x0200  # Compatible with P.M. Windowing
    NEWINAPI = 0x0300  # Uses P.M. Windowing API
    NEAPPTYP = 0x0700  # Application type mask
    NEBOUND = 0x0800  # Bound Family/API
    NEIERR = 0x2000  # Errors in image
    NEPRIVLIB = 0x4000  # A one customer Windows 3.0 library
    NENOTP = 0x8000  # Not a process


class NETargetOSFlags(IntEnum):
    NE_UNKNOWN = 0  # Unknown (any "new-format" OS)
    NE_OS2 = 1  # OS/2 (default)
    NE_WINDOWS = 2  # Windows
    NE_DOS = 3  # DOS 4.x
    NE_DEV386 = 4  # Windows 386


@dataclasses.dataclass(frozen=True)
class NESegmentTableEntry:
    ns_sector: int  # File sector of start of segment
    ns_cbseg: int  # Number of bytes in file
    ns_flags: int  # Attribute flags
    ns_minalloc: int  # Minimum allocation in bytes

    def has_reloc(self) -> bool:
        return self.ns_flags & 0x100 == 0x100

    @classmethod
    def from_memory(
        cls, data: ConcreteBuffer, offset: int, count: int
    ) -> tuple[tuple["NESegmentTableEntry", ...], int]:
        struct_fmt = "<4H"
        struct_size = struct.calcsize(struct_fmt)
        items = tuple(
            cls(*items)
            for items in struct.iter_unpack(
                struct_fmt, data[offset : offset + count * struct_size]
            )
        )
        return items, offset + count * struct_size


class NERelocationType(Enum):
    LOBYTE = 0x00
    SEGMENT = 0x02
    FAR_ADDR = 0x03
    OFFSET = 0x05


class NERelocationFlag(Enum):
    INTERNALREF = 0
    IMPORTORDINAL = 1
    IMPORTNAME = 2
    OSFIXUP = 3


@dataclasses.dataclass(frozen=True)
class NERelocation:
    type: NERelocationType
    flag: NERelocationFlag
    offsets: tuple[int, ...]
    value0: int
    value1: int


NERelocations = tuple[NERelocation, ...]


def iter_relocations(
    data: Buffer, offset: int = 0
) -> Iterator[tuple[int, int, int, int, int]]:
    """Read raw values from the relocation table.
    The first word is the number of 8-byte relocations that follow.
    This is not a complete NERelocation because we need to read the chain of offsets
    to collect all relocation sites."""
    (n_reloc,) = struct.unpack_from("<H", data, offset=offset)
    offset += 2

    for _ in range(n_reloc):
        yield struct.unpack_from("<BBHHH", data, offset=offset)
        offset += 8


def iter_reloc_chain(data: Buffer, start: int) -> Iterator[int]:
    """Using the segment contents in `data`, iterate each relocation site by following the
    chain of offsets that begins at offset `start`. 0xFFFF signals the end of the chain.
    """
    value = start
    while value != 0xFFFF:
        yield value
        (value,) = struct.unpack_from("<H", data, offset=value)


def iter_segments(
    view: memoryview, seg_tab_offset: int, seg_count: int, sector_size: int
) -> Iterator[tuple[ImageSection, NERelocations]]:
    """Creates an ImageSection for each segment in the NE segment table.
    We also return the list of relocations for each segment.
    The reason to return both here is that we need the segment table to tell whether
    the segment has any relocations and the segment's data to collect all relocation sites
    by iterating on the chained values."""
    segment_table, _ = NESegmentTableEntry.from_memory(
        view, offset=seg_tab_offset, count=seg_count
    )

    for i, entry in enumerate(segment_table):
        # Advance the segment number by 8 for each segment.
        # It is critical to match Ghidra's behavior so that our import tool will work.
        # See: ghidra.program.model.address.ProtectedAddressSpace::getNextOpenSegment
        virtual_address = (0x1000 + 8 * i) << 16
        virtual_size = entry.ns_minalloc if entry.ns_minalloc != 0 else 0x10000

        if entry.ns_sector == 0:
            # No physical data. The segment is entirely virtual.
            physical_offset = 0
            physical_size = 0
        else:
            physical_offset = entry.ns_sector * sector_size
            physical_size = entry.ns_cbseg if entry.ns_cbseg != 0 else 0x10000

        seg_data = view[physical_offset:][:physical_size]

        relocs = []

        if physical_size > 0 and entry.has_reloc():
            # The relocation table directly follows the end of physical data for the segment.
            reloc_table = view[physical_offset + physical_size :]

            for reloc_type, reloc_flag, start, value0, value1 in iter_relocations(
                reloc_table
            ):
                additive = reloc_flag & 4 == 4

                offsets: tuple[int, ...]
                # Do not follow the chain if the additive flag is set.
                if additive:
                    # TODO: GH #325. Skip this for now. Even Ghidra doesn't handle it.
                    offsets = tuple()
                else:
                    offsets = tuple(iter_reloc_chain(seg_data, start))

                reloc = NERelocation(
                    type=NERelocationType(reloc_type),
                    flag=NERelocationFlag(reloc_flag & 3),  # Mask out additive flag
                    offsets=offsets,
                    value0=value0,
                    value1=value1,
                )
                relocs.append(reloc)

        yield (
            ImageSection(
                virtual_range=range(virtual_address, virtual_address + virtual_size),
                physical_range=range(physical_offset, physical_offset + physical_size),
                view=seg_data,
            ),
            tuple(relocs),
        )


@dataclasses.dataclass(frozen=True)
class NEEntry:
    ordinal: int
    movable: bool
    exported: bool
    g_dataseg: bool
    segment: int
    offset: int

    @classmethod
    def from_memory(cls, data: Buffer, offset: int = 0) -> tuple["NEEntry", ...]:
        ordinal = 0
        entries = []

        while True:
            n_entries, indicator = struct.unpack_from("<2B", data, offset)
            if n_entries == 0:
                break

            offset += 2
            for _ in range(n_entries):
                ordinal += 1  # Ordinals start at 1.
                if indicator == 255:
                    flag, entry_seg, entry_ofs = struct.unpack_from(
                        "<BxxBH", data, offset
                    )
                    entry = cls(
                        ordinal=ordinal,
                        movable=True,
                        exported=flag & 1 == 1,
                        g_dataseg=flag & 2 == 2,
                        segment=entry_seg,
                        offset=entry_ofs,
                    )
                    entries.append(entry)
                    offset += 6

                elif indicator == 0:
                    # Skip this ordinal number.
                    offset += 1

                else:
                    # Indicator is the segment number for all in this bundle.
                    flag, entry_ofs = struct.unpack_from("<BH", data, offset)
                    entry = cls(
                        ordinal=ordinal,
                        movable=False,
                        exported=flag & 1 == 1,
                        g_dataseg=flag & 2 == 2,
                        segment=indicator,
                        offset=entry_ofs,
                    )
                    entries.append(entry)
                    offset += 3

        return tuple(entries)


@dataclasses.dataclass(frozen=True)
class NewExeHeader:
    # pylint: disable=too-many-instance-attributes
    ne_magic: bytes  # Magic number NE_MAGIC
    ne_ver: int  # Version number
    ne_rev: int  # Revision number
    ne_enttab: int  # Offset of Entry Table
    ne_cbenttab: int  # Number of bytes in Entry Table
    ne_crc: int  # Checksum of whole file
    ne_flags: NESegmentFlags  # Flag word
    ne_autodata: int  # Automatic data segment number
    ne_heap: int  # Initial heap allocation
    ne_stack: int  # Initial stack allocation
    ne_csip: tuple[int, int]  # Initial CS:IP setting
    ne_sssp: tuple[int, int]  # Initial SS:SP setting
    ne_cseg: int  # Count of file segments
    ne_cmod: int  # Entries in Module Reference Table
    ne_cbnrestab: int  # Size of non-resident name table
    ne_segtab: int  # Offset of Segment Table (Relative to NE header)
    ne_rsrctab: int  # Offset of Resource Table (Relative to NE header)
    ne_restab: int  # Offset of resident name Table (Relative to NE header)
    ne_modtab: int  # Offset of Module Reference Table (Relative to NE header)
    ne_imptab: int  # Offset of Imported Names Table (Relative to NE header)
    ne_nrestab: int  # Offset of Non-resident Names Table (File offset)
    ne_cmovent: int  # Count of movable entries
    ne_align: int  # Segment alignment shift count (Sector size is 1 << ne_align)
    ne_cres: int  # Count of resource entries
    ne_exetyp: NETargetOSFlags  # Target operating system
    ne_flagsothers: int  # Other .EXE flags
    ne_pretthunks: int  # Windows 3.0 - offset to return thunks
    ne_psegrefbytes: int  # Windows 3.0 - offset to segment ref. bytes
    ne_swaparea: int  # Windows 3.0 - minimum code swap size
    ne_expver: int  # Windows 3.0 - expected windows version number

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["NewExeHeader", int]:
        if not cls.taste(data, offset):
            raise ValueError
        struct_fmt = "<2s2B2HI16HI3H2B4H"
        struct_size = struct.calcsize(struct_fmt)
        # fmt: off
        items: tuple[bytes, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int] = (
            struct.unpack_from(struct_fmt, data, offset)
        )
        # fmt: on
        result = cls(
            *items[:6],
            NESegmentFlags(items[6]),
            *items[7:10],
            (items[11], items[10]),  # CS:IP
            (items[13], items[12]),  # SS:SP
            *items[14:26],
            NETargetOSFlags(items[26]),
            *items[27:],
        )
        return result, offset + struct_size

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        (magic,) = struct.unpack_from("<2s", data, offset)
        return magic == b"NE"


@dataclasses.dataclass
class NEImage(Image):
    mz_header: ImageDosHeader
    header: NewExeHeader
    section_relocations: tuple[NERelocations, ...] = tuple()
    _imports: tuple[ImageImport, ...] = tuple()

    @classmethod
    def from_memory(
        cls, data: bytes, mz_header: ImageDosHeader, filepath: Path
    ) -> "NEImage":
        offset = mz_header.e_lfanew
        # n.b. The memoryview must be writeable for reloc replacement.
        view = memoryview(bytearray(data))
        header, _ = NewExeHeader.from_memory(data, offset=offset)
        sections, section_relocations = zip(
            *iter_segments(
                view,
                seg_tab_offset=offset + header.ne_segtab,
                seg_count=header.ne_cseg,
                sector_size=(1 << header.ne_align),
            )
        )

        return cls(
            filepath=filepath,
            data=data,
            view=view,
            mz_header=mz_header,
            header=header,
            sections=sections,
            section_relocations=section_relocations,
        )

    def get_module_name(self, index: int) -> str:
        modules_raw = self.view[
            self.mz_header.e_lfanew
            + self.header.ne_modtab : self.mz_header.e_lfanew
            + self.header.ne_imptab
        ]
        modules = tuple(v for v, in struct.iter_unpack("<H", modules_raw))
        return self.get_imported_name(modules[index - 1])

    def get_imported_name(self, offset: int) -> str:
        import_names_raw = self.view[
            self.mz_header.e_lfanew
            + self.header.ne_imptab : self.mz_header.e_lfanew
            + self.header.ne_enttab
        ]
        return pascal_string(import_names_raw, offset)

    def get_import_mapping(self) -> Mapping[tuple[int, int | str], ImageImport]:
        """Searches each section's relocation table for imported functions, then
        assigns a dummy address for each. The import addresses are ordered to match Ghidra
        although this is not of utmost importance. The returned mapping connects
        (module_id, name or ordinal_idx) to ImageImport so that we can easily substitute
        the dummy address when applying relocation patches."""

        def import_tuple_generator() -> Iterator[tuple[int, int | str]]:
            """Flattens the list of relocations across all sections
            to collect each import by ordinal or name."""
            for relocations in self.section_relocations:
                for r in relocations:
                    if r.flag == NERelocationFlag.IMPORTORDINAL:
                        yield (r.value0, r.value1)

                    elif r.flag == NERelocationFlag.IMPORTNAME:
                        yield (r.value0, self.get_imported_name(r.value1))

        # Remove duplicates
        all_imports = set(import_tuple_generator())

        def ordinal_name_keyfn(imp: tuple[int, int | str]) -> tuple[int, str]:
            """Sorts named and ordinal imports to match Ghidra's ordering.
            See ghidra.program.model.symbol.SymbolUtilities::ORDINAL_PREFIX."""
            if isinstance(imp[1], int):
                return (imp[0], f"Ordinal_{imp[1]:05}")

            return (imp[0], imp[1])

        sorted_imports = sorted(all_imports, key=ordinal_name_keyfn)

        def generator() -> Iterator[tuple[tuple[int, int | str], ImageImport]]:
            # Ghidra creates a dummy segment for each NE resource, followed by the import table.
            # We don't do anything with resources yet, so just use a value large enough
            # to not intrude on any real segments.
            import_seg = 0x2000

            for i, reloc_key in enumerate(sorted_imports):
                module_id, func_id = reloc_key
                module_name = self.get_module_name(module_id)
                # Assumes 4 bytes per import to match Ghidra.
                # See: ghidra.app.util.opinion.NELoader::processModuleReferenceTable
                addr = (import_seg << 16) + (4 * i)

                if isinstance(func_id, int):
                    yield (
                        reloc_key,
                        ImageImport(module=module_name, ordinal=func_id, addr=addr),
                    )
                else:
                    yield (
                        reloc_key,
                        ImageImport(module=module_name, name=func_id, addr=addr),
                    )

        return MappingProxyType(dict(generator()))

    def __post_init__(self):
        entry_table = NEEntry.from_memory(
            self.view, self.mz_header.e_lfanew + self.header.ne_enttab
        )

        entry_map = {entry.ordinal: entry for entry in entry_table}

        import_map = self.get_import_mapping()
        self._imports = tuple(import_map.values())

        for seg, relocations in zip(self.sections, self.section_relocations):
            seg_data = seg.view

            # Each location to patch in this segment.
            reloc_values: list[tuple[int, bytes]] = []

            for reloc in relocations:
                match reloc.flag:
                    case NERelocationFlag.IMPORTORDINAL:
                        replacement = struct.pack(
                            "<I", import_map[(reloc.value0, reloc.value1)].addr
                        )

                    case NERelocationFlag.IMPORTNAME:
                        replacement = struct.pack(
                            "<I",
                            import_map[
                                (reloc.value0, self.get_imported_name(reloc.value1))
                            ].addr,
                        )

                    case NERelocationFlag.INTERNALREF:
                        replacement_seg, replacement_ofs = (
                            reloc.value0,
                            reloc.value1,
                        )

                        if reloc.value0 == 255:
                            # Movable segment. Lookup using 1-based ordinal number.
                            entry = entry_map[reloc.value1]
                            replacement_seg, replacement_ofs = (
                                entry.segment,
                                entry.offset,
                            )

                        if reloc.type == NERelocationType.LOBYTE:
                            # TODO: GH #325
                            pass

                        elif reloc.type == NERelocationType.OFFSET:
                            replacement = struct.pack("<H", replacement_ofs)

                        elif reloc.type == NERelocationType.SEGMENT:
                            start_addr = self.get_abs_addr(replacement_seg, 0)
                            replacement = struct.pack("<H", (start_addr >> 16))

                        elif reloc.type == NERelocationType.FAR_ADDR:
                            replacement = struct.pack(
                                "<I",
                                self.get_abs_addr(replacement_seg, replacement_ofs),
                            )

                    case NERelocationFlag.OSFIXUP:
                        # TODO: GH #325. Ghidra does not handle these either.
                        # We need to see an example to know what to do.
                        continue

                # TODO: GH #325. Additive relocations are ignored and reloc.offsets will be empty.
                reloc_values.extend([(offset, replacement) for offset in reloc.offsets])

            # Now apply the patches
            for offset, patch in reloc_values:
                seg_data[offset : offset + len(patch)] = patch

        # The data has been changed: update underlying value.
        self.data = bytes(self.view)

    @property
    def imagebase(self):
        return 0x10000000

    @property
    def imports(self) -> Iterator[ImageImport]:
        return iter(self._imports)

    @property
    def entry(self) -> int:
        return self.get_abs_addr(*self.header.ne_csip)

    def _get_segment(self, index: int) -> ImageSection:
        try:
            assert index > 0
            return self.sections[index - 1]
        except (AssertionError, IndexError) as ex:
            raise SectionNotFoundError(index) from ex

    def is_valid_vaddr(self, _: int) -> bool:
        return True  # TODO

    def get_relative_addr(self, addr: int) -> tuple[int, int]:
        for i, segment in enumerate(self.sections):
            if addr in segment.virtual_range:
                return (i + 1, addr - segment.virtual_address)

        raise InvalidVirtualAddressError(f"{self.filepath} : 0x{addr:x}")

    def get_abs_addr(self, section: int, offset: int) -> int:
        try:
            segment = self.sections[section - 1]
            return segment.virtual_address + offset
        except IndexError as ex:
            raise InvalidVirtualAddressError(f"{section:04x}:{offset:04x}") from ex

    def seek(self, vaddr: int) -> tuple[memoryview, int]:
        segment, offset = self.get_relative_addr(vaddr)
        seg = self._get_segment(segment)

        if offset > seg.virtual_size:
            raise InvalidVirtualAddressError(f"{segment:04x}:{offset:04x}")

        if seg.size_of_raw_data == 0:
            return (memoryview(b""), seg.virtual_size - offset)

        return (seg.view[offset:], seg.virtual_size - offset)

    def get_code_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError

    def get_data_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError

    def get_const_regions(self) -> Iterator[ImageRegion]:
        raise NotImplementedError
