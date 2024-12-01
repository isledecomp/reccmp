from enum import IntEnum, IntFlag
import logging
from pathlib import Path
import struct
import bisect
from functools import cached_property
from typing import Iterator, List, Optional, Tuple
from dataclasses import dataclass


class MZHeaderNotFoundError(Exception):
    """MZ magic string not found at the start of the binary."""


class PEHeaderNotFoundError(Exception):
    """PE magic string not found at the offset given in 0x3c."""


class UnknownPEMachine(ValueError):
    """The PE binary has an unknown machine architecture."""


class SectionNotFoundError(KeyError):
    """The specified section was not found in the file."""


class InvalidVirtualAddressError(IndexError):
    """The given virtual address is too high or low
    to point to something in the binary file."""


# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class ImageDosHeader:
    # Order is significant!
    e_magic: int
    e_cblp: int
    e_cp: int
    e_crlc: int
    e_cparhdr: int
    e_minalloc: int
    e_maxalloc: int
    e_ss: int
    e_sp: int
    e_csum: int
    e_ip: int
    e_cs: int
    e_lfarlc: int
    e_ovno: int
    e_res: tuple[int, int, int, int]
    e_oemid: int
    e_oeminfo: int
    e_res2: tuple[int, int, int, int, int, int, int, int, int, int]
    e_lfanew: int

    @classmethod
    def from_memory(cls, view: memoryview, offset: 0) -> tuple["ImageDosHeader", int]:
        struct_fmt = "<30HI"
        items = struct.unpack_from(struct_fmt, view[:64], offset)
        result = cls(
            *items[:14],
            tuple(items[14:18]),
            *items[18:20],
            tuple(tuple[20:30]),
            items[30],
        )
        return result, offset + struct.calcsize(struct_fmt)


class PeMachine(IntEnum):
    IMAGE_FILE_MACHINE_ALPHA = 0x184
    IMAGE_FILE_MACHINE_ALPHA64 = 0x284
    IMAGE_FILE_MACHINE_AM33 = 0x1D3
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM = 0x1C0
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64
    IMAGE_FILE_MACHINE_ARMNT = 0x1C4
    IMAGE_FILE_MACHINE_AXP64 = 0x284
    IMAGE_FILE_MACHINE_EBC = 0xEBC
    IMAGE_FILE_MACHINE_I386 = 0x14C
    IMAGE_FILE_MACHINE_IA64 = 0x200
    IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232
    IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264
    IMAGE_FILE_MACHINE_M32R = 0x9041
    IMAGE_FILE_MACHINE_MIPS16 = 0x266
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
    IMAGE_FILE_MACHINE_POWERPC = 0x1F0
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1F1
    IMAGE_FILE_MACHINE_R4000 = 0x166
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128
    IMAGE_FILE_MACHINE_SH3 = 0x1A2
    IMAGE_FILE_MACHINE_SH3DSP = 0x1A3
    IMAGE_FILE_MACHINE_SH4 = 0x1A6
    IMAGE_FILE_MACHINE_SH5 = 0x1A8
    IMAGE_FILE_MACHINE_THUMB = 0x1C2
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169


class PeCharacteristics(IntFlag):
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010
    IMAGE_FILE_LARGE_ADDRESS_ = 0x0020
    IMAGE_FILE_RESERVED_0X40 = 0x0040
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200
    IMAGE_FILE_REMOVABLE_RUN_ = 0x0400
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
    IMAGE_FILE_SYSTEM = 0x1000
    IMAGE_FILE_DLL = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000


@dataclass(frozen=True)
class PEHeader:
    # Order is significant!
    signature: bytes
    machine: int
    number_of_sections: int
    time_date_stamp: int
    pointer_to_symbol_table: int  # deprecated
    number_of_symbols: int  # deprecated
    size_of_optional_header: int
    characteristics: PeCharacteristics

    @classmethod
    def from_memory(cls, view: memoryview, offset: int) -> tuple["PEHeader", int]:
        if view[offset : offset + 4] != b"PE\x00\x00":
            raise PEHeaderNotFoundError
        struct_fmt = "<4s2H3I2H"
        items = list(struct.unpack_from(struct_fmt, view, offset=offset))
        offset += struct.calcsize(struct_fmt)
        try:
            items[1] = PeMachine(items[1])
        except ValueError as e:
            raise UnknownPEMachine(f"0x{items[1]:x}") from e
        items[7] = PeCharacteristics(items[7])
        return cls(*items), offset


class WindowsSubsystem(IntEnum):
    IMAGE_SUBSYSTEM_UNKNOWN = 0
    IMAGE_SUBSYSTEM_NATIVE = 1
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    IMAGE_SUBSYSTEM_OS2_CUI = 5
    IMAGE_SUBSYSTEM_POSIX_CUI = 7
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
    IMAGE_SUBSYSTEM_EFI_ROM = 13
    IMAGE_SUBSYSTEM_XBOX = 14
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16


class DllCharacteristics(IntFlag):
    IMAGE_DLLCHARACTERISTICS_RESERVED_0X0001 = 0x0001
    IMAGE_DLLCHARACTERISTICS_RESERVED_0X0002 = 0x0002
    IMAGE_DLLCHARACTERISTICS_RESERVED_0X0004 = 0x0004
    IMAGE_DLLCHARACTERISTICS_RESERVED_0X0008 = 0x0008
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000


class DataDirectoryItemType(IntEnum):
    EXPORT_TABLE = 0
    IMPORT_TABLE = 1
    RESOURCE_TABLE = 2
    EXCEPTION_TABLE = 3
    CERTIFICATE_TABLE = 4
    BASE_RELOCATION_TABLE = 5
    DEBUG = 6
    ARCHITECTURE = 7
    GLOBAL_PTR = 8
    TLS_TABLE = 9
    LOAD_CONFIG_TABLE = 10
    BOUND_IMPORT = 11
    IAT = 12
    DELAY_IMPORT_DESCRIPTOR = 13
    CLR_RUNTIME_HEADER = 14
    RESERVED_INDEX_0XF = 15


@dataclass
class DataDirectoryItemHeader:
    # Order is significant!
    virtual_address: int
    virtual_size: int


@dataclass
class DataDirectoryItemRegion:
    virtual_address: int
    virtual_size: int


@dataclass(frozen=True)
class PeOptionalHeader:
    # Order is significant!
    magic: int
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int
    base_of_data: Optional[int]
    image_base: int
    section_alignment: int
    file_alignment: int
    major_operating_system_version: int
    minor_operating_system_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    win32_version_value: int
    size_of_image: int
    size_of_headers: int
    check_sum: int
    subsystem: WindowsSubsystem
    dll_characteristics: DllCharacteristics
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    loader_flags: int  # _reserved, always 0
    number_of_rva_and_sizes: int
    directories: tuple[DataDirectoryItemHeader, ...]

    @classmethod
    def from_memory(
        cls, view: memoryview, offset: int
    ) -> tuple["PeOptionalHeader", int]:
        struct_fmt1 = "<H2B5I"
        part1 = struct.unpack_from(struct_fmt1, view, offset=offset)
        assert part1[0] in (0x10B, 0x20B)  # PE32, PE32+
        pe32_plus = part1[0] == 0x20B
        base_of_data = None
        struct_fmt2 = "<"
        offset += struct.calcsize(struct_fmt1)
        if not pe32_plus:
            struct_fmt2 = "<I"
            (base_of_data,) = struct.unpack_from(struct_fmt2, view, offset=offset)
        offset += struct.calcsize(struct_fmt2)
        if pe32_plus:
            struct_fmt3 = "<QII6H4I2H4Q2I"
            part3 = struct.unpack_from(struct_fmt3, view, offset=offset)
        else:
            struct_fmt3 = "<III6H4I2H4I2I"
            part3 = struct.unpack_from(struct_fmt3, view, offset=offset)
        part3 = list(part3)
        part3[13] = WindowsSubsystem(part3[13])
        part3[14] = DllCharacteristics(part3[14])
        offset += struct.calcsize(struct_fmt3)

        count_directories = part3[-1]
        directories = tuple(
            DataDirectoryItemHeader(*item)
            for item in struct.iter_unpack(
                "<II", view[offset : offset + 8 * count_directories]
            )
        )
        offset += 8 * count_directories
        return cls(*part1, base_of_data, *part3, directories), offset


class SectionFlags(IntFlag):
    IMAGE_SCN_RESERVED_0X0 = 0x00000000
    IMAGE_SCN_RESERVED_0X1 = 0x00000001
    IMAGE_SCN_RESERVED_0X2 = 0x00000002
    IMAGE_SCN_RESERVED_0X4 = 0x00000004
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008
    IMAGE_SCN_RESERVED_0X10 = 0x00000010
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_RESERVED_0X400 = 0x00000400
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_GPREL = 0x00008000
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_16BIT = 0x00020000
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    # IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    # IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    # IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    # IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    # IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    # IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    # IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    # IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    # IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    # IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    # IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    # IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    # IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    # IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000


@dataclass(frozen=True)
class ImageSectionHeader:
    name: str  # Name
    virtual_size: int  # VirtualSize
    virtual_address: int  # VirtualAddress
    size_of_raw_data: int  # SizeOfRawData
    pointer_to_raw_data: int  # PointerToRawData
    pointer_to_relocations: int  # PointerToRelocations
    pointer_to_line_numbers: int  # NumberOfRelocations
    number_of_relocations: int  # NumberOfLineNumbers
    number_of_line_numbers: SectionFlags  # Characteristics

    @classmethod
    def from_memory(
        cls, view: memoryview, offset: int, count: int
    ) -> tuple[tuple["ImageSectionHeader", ...], int]:
        struct_fmt = "<8s8I"
        s_size = struct.calcsize(struct_fmt)
        items = tuple(
            cls(
                members[0].decode("ascii").rstrip("\x00"),
                *members[1:-1],
                SectionFlags(members[-1]),
            )
            for members in struct.iter_unpack(
                struct_fmt, view[offset : offset + count * s_size]
            )
        )
        return items, offset + count * struct.calcsize(struct_fmt)


@dataclass(frozen=True)
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    view: memoryview

    @cached_property
    def size_of_raw_data(self) -> int:
        return len(self.view)

    @cached_property
    def extent(self):
        """Get the highest possible offset of this section"""
        return max(self.size_of_raw_data, self.virtual_size)

    def match_name(self, name: str) -> bool:
        return self.name == name

    def contains_vaddr(self, vaddr: int) -> bool:
        return self.virtual_address <= vaddr < self.virtual_address + self.extent

    def read_virtual(self, vaddr: int, size: int) -> memoryview:
        ofs = vaddr - self.virtual_address

        # Negative index will read from the end, which we don't want
        if ofs < 0:
            raise InvalidVirtualAddressError

        try:
            return self.view[ofs : ofs + size]
        except IndexError as ex:
            raise InvalidVirtualAddressError from ex

    def addr_is_uninitialized(self, vaddr: int) -> bool:
        """We cannot rely on the IMAGE_SCN_CNT_UNINITIALIZED_DATA flag (0x80) in
        the characteristics field so instead we determine it this way."""
        if not self.contains_vaddr(vaddr):
            return False

        # Should include the case where size_of_raw_data == 0,
        # meaning the entire section is uninitialized
        return (self.virtual_size > self.size_of_raw_data) and (
            vaddr - self.virtual_address >= self.size_of_raw_data
        )


@dataclass(frozen=True)
class ExportDirectoryTable:
    # Order is significant!
    export_flags: int
    time_date_stamp: int
    major_version: int
    minor_version: int
    name_rva: int
    ordinal_base: int
    address_table_entries: int
    number_of_name_pointers: int
    export_address_table_rva: int
    name_pointer_rva: int
    ordinal_table_rva: int


logger = logging.getLogger(__name__)


class Bin:
    """Parses a PE format EXE and allows reading data from a virtual address.
    Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"""

    # pylint: disable=too-many-instance-attributes

    def __init__(self, filename: Path | str, find_str: bool = False) -> None:
        logger.debug('Parsing headers of "%s"... ', filename)
        self.filename = str(filename)
        self.view: memoryview = None
        self.imagebase = None
        self.data_directories: list[DataDirectoryItemRegion] = None
        self.entry = None
        self.sections: List[Section] = []
        self._section_vaddr: List[int] = []
        self.find_str = find_str
        self._potential_strings = {}
        self._relocations = set()
        self._relocated_addrs = set()
        self.imports = []
        self.thunks = []
        self.exports: List[Tuple[int, str]] = []
        self.is_debug: bool = False

    def __enter__(self):
        logger.debug("Bin %s Enter", self.filename)
        with open(self.filename, "rb") as f:
            self.view = memoryview(f.read())

        (mz_str,) = struct.unpack("2s", self.view[0:2])
        if mz_str != b"MZ":
            raise MZHeaderNotFoundError

        mz_header, _ = ImageDosHeader.from_memory(self.view, offset=0)

        # PE header offset is absolute, so seek there
        pe_hdr, offset_pe_optional = PEHeader.from_memory(
            self.view, offset=mz_header.e_lfanew
        )

        if pe_hdr.machine != PeMachine.IMAGE_FILE_MACHINE_I386:
            raise ValueError(f"reccmp only supports i386 binaries: {pe_hdr.machine}.")

        optional_hdr, offset_sections = PeOptionalHeader.from_memory(
            self.view, offset=offset_pe_optional
        )
        self.imagebase = optional_hdr.image_base
        self.entry = optional_hdr.address_of_entry_point + self.imagebase

        self.data_directories = [
            DataDirectoryItemRegion(
                virtual_address=self.imagebase + directory.virtual_address
                if directory.virtual_address
                else 0,
                virtual_size=directory.virtual_size,
            )
            for directory in optional_hdr.directories
        ]

        # Check for presence of .debug subsection in .rdata
        try:
            if (
                self.data_directories[DataDirectoryItemType.DEBUG.value].virtual_address
                != 0
            ):
                self.is_debug = True
        except IndexError:
            pass

        image_section_headers, _ = ImageSectionHeader.from_memory(
            self.view, count=pe_hdr.number_of_sections, offset=offset_sections
        )

        self.sections = [
            Section(
                name=image_section_header.name,
                virtual_address=self.imagebase + image_section_header.virtual_address,
                virtual_size=image_section_header.virtual_size,
                view=self.view[
                    image_section_header.pointer_to_raw_data : image_section_header.pointer_to_raw_data
                    + image_section_header.size_of_raw_data
                ],
            )
            for image_section_header in image_section_headers
        ]

        # bisect does not support key on the GitHub CI version of python
        self._section_vaddr = [section.virtual_address for section in self.sections]

        self._populate_relocations()
        self._populate_imports()
        self._populate_thunks()
        # Export dir is always first
        self._populate_exports(
            optional_hdr.directories[DataDirectoryItemType.EXPORT_TABLE].virtual_address
        )

        # This is a (semi) expensive lookup that is not necesssary in every case.
        # We can find strings in the original if we have coverage using STRING markers.
        # For the recomp, we can find strings using the PDB.
        if self.find_str:
            self._prepare_string_search()

        logger.debug("... Parsing finished")
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        logger.debug("Bin %s Exit", self.filename)
        self.view.release()

    def get_relocated_addresses(self) -> List[int]:
        return sorted(self._relocated_addrs)

    def find_string(self, target: str) -> Optional[int]:
        # Pad with null terminator to make sure we don't
        # match on a subset of the full string
        if not target.endswith(b"\x00"):
            target += b"\x00"

        c = target[0]
        if c not in self._potential_strings:
            return None

        for addr in self._potential_strings[c]:
            if target == self.read(addr, len(target)):
                return addr

        return None

    def is_relocated_addr(self, vaddr) -> bool:
        return vaddr in self._relocated_addrs

    def _prepare_string_search(self):
        """We are interested in deduplicated string constants found in the
        .rdata and .data sections. For each relocated address in these sections,
        read the first byte and save the address if that byte is an ASCII character.
        When we search for an arbitrary string later, we can narrow down the list
        of potential locations by a lot."""

        def is_ascii(b):
            return b" " <= b < b"\x7f"

        sect_data = self.get_section_by_name(".data")
        sect_rdata = self.get_section_by_name(".rdata")
        potentials = filter(
            lambda a: sect_data.contains_vaddr(a) or sect_rdata.contains_vaddr(a),
            self.get_relocated_addresses(),
        )

        for addr in potentials:
            c = self.read(addr, 1)
            if c is not None and is_ascii(c):
                k = ord(c)
                if k not in self._potential_strings:
                    self._potential_strings[k] = set()

                self._potential_strings[k].add(addr)

    def get_sections_in_data_directory(self, t: DataDirectoryItemType) -> list[Section]:
        result = []
        data_region = self.data_directories[t.value]
        for section in self.sections:
            if (
                data_region.virtual_address
                <= section.virtual_address
                < data_region.virtual_address + data_region.virtual_size
            ):
                result.append(section)
        return result

    def _populate_relocations(self):
        """The relocation table in .reloc gives each virtual address where the next four
        bytes are, itself, another virtual address. During loading, these values will be
        patched according to the virtual address space for the image, as provided by Windows.
        We can use this information to get a list of where each significant "thing"
        in the file is located. Anything that is referenced absolutely (i.e. excluding
        jump destinations given by local offset) will be here.
        One use case is to tell whether an immediate value in an operand represents
        a virtual address or just a big number."""

        reloc_sections = self.get_sections_in_data_directory(
            DataDirectoryItemType.BASE_RELOCATION_TABLE
        )
        reloc_addrs = []

        for reloc_section in reloc_sections:
            reloc = reloc_section.view
            ofs = 0

            # Parse the structure in .reloc to get the list locations to check.
            # The first 8 bytes are 2 dwords that give the base page address
            # and the total block size (including this header).
            # The page address is used to compact the list; each entry is only
            # 2 bytes, and these are added to the base to get the full location.
            # If the entry read in is zero, we are at the end of this section and
            # these are padding bytes.
            while True:
                (page_base, block_size) = struct.unpack("<2I", reloc[ofs : ofs + 8])
                if block_size == 0:
                    break

                # HACK: ignore the relocation type for now (the top 4 bits of the value).
                values = list(
                    struct.iter_unpack("<H", reloc[ofs + 8 : ofs + block_size])
                )
                reloc_addrs += [
                    self.imagebase + page_base + (v[0] & 0xFFF)
                    for v in values
                    if v[0] != 0
                ]

                ofs += block_size

        # We are now interested in the relocated addresses themselves. Seek to the
        # address where there is a relocation, then read the four bytes into our set.
        reloc_addrs.sort()
        self._relocations = set(reloc_addrs)

        for section_id, offset in map(self.get_relative_addr, reloc_addrs):
            section = self.get_section_by_index(section_id)
            (relocated_addr,) = struct.unpack("<I", section.view[offset : offset + 4])
            self._relocated_addrs.add(relocated_addr)

    def find_float_consts(self) -> Iterator[Tuple[int, int, float]]:
        """Floating point instructions that refer to a memory address can
        point to constant values. Search the code sections to find FP
        instructions and check whether the pointer address refers to
        read-only data."""

        # TODO: Should check any section that has code, not just .text
        text = self.get_section_by_name(".text")
        rdata = self.get_section_by_name(".rdata")

        # These are the addresses where a relocation occurs.
        # Meaning: it points to an absolute address of something
        for addr in self._relocations:
            if not text.contains_vaddr(addr):
                continue

            # Read the two bytes before the relocated address.
            # We will check against possible float opcodes
            raw = text.read_virtual(addr - 2, 6)
            (opcode, opcode_ext, const_addr) = struct.unpack("<BBL", raw)

            # Skip right away if this is not const data
            if not rdata.contains_vaddr(const_addr):
                continue

            if opcode_ext in (0x5, 0xD, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
                if opcode in (0xD8, 0xD9):
                    # dword ptr -- single precision
                    (float_value,) = struct.unpack("<f", self.read(const_addr, 4))
                    yield (const_addr, 4, float_value)

                elif opcode in (0xDC, 0xDD):
                    # qword ptr -- double precision
                    (float_value,) = struct.unpack("<d", self.read(const_addr, 8))
                    yield (const_addr, 8, float_value)

    def _populate_imports(self):
        """Parse .idata to find imported DLLs and their functions."""
        import_directory = self.data_directories[
            DataDirectoryItemType.IMPORT_TABLE.value
        ]

        def iter_image_import(offset: int):
            while True:
                # Read 5 dwords until all are zero.
                image_import_descriptor = struct.unpack("<5I", self.read(offset, 20))
                offset += 20
                if all(x == 0 for x in image_import_descriptor):
                    break

                (rva_ilt, _, __, dll_name, rva_iat) = image_import_descriptor
                # Convert relative virtual addresses into absolute
                yield (
                    self.imagebase + rva_ilt,
                    self.imagebase + dll_name,
                    self.imagebase + rva_iat,
                )

        image_import_descriptors = list(
            descriptor
            for descriptor in iter_image_import(import_directory.virtual_address)
        )

        def iter_imports():
            # ILT = Import Lookup Table
            # IAT = Import Address Table
            # ILT gives us the symbol name of the import.
            # IAT gives the address. The compiler generated a thunk function
            # that jumps to the value of this address.
            for start_ilt, dll_addr, start_iat in image_import_descriptors:
                dll_name = self.read_string(dll_addr).decode("ascii")
                ofs_ilt = start_ilt
                # Address of "__imp__*" symbols.
                ofs_iat = start_iat
                while True:
                    (lookup_addr,) = struct.unpack("<L", self.read(ofs_ilt, 4))
                    (import_addr,) = struct.unpack("<L", self.read(ofs_iat, 4))
                    if lookup_addr == 0 or import_addr == 0:
                        break

                    # MSB set if this is an ordinal import
                    if lookup_addr & 0x80000000 != 0:
                        ordinal_num = lookup_addr & 0x7FFF
                        symbol_name = f"Ordinal_{ordinal_num}"
                    else:
                        # Skip the "Hint" field, 2 bytes
                        name_ofs = lookup_addr + self.imagebase + 2
                        symbol_name = self.read_string(name_ofs).decode("ascii")

                    yield (dll_name, symbol_name, ofs_iat)
                    ofs_ilt += 4
                    ofs_iat += 4

        self.imports = list(iter_imports())

    def _populate_thunks(self):
        """For each imported function, we generate a thunk function. The only
        instruction in the function is a jmp to the address in .idata.
        Search .text to find these functions."""

        text_sect = self.get_section_by_name(".text")
        text_start = text_sect.virtual_address

        # If this is a debug build, read the thunks at the start of .text
        # Terminated by a big block of 0xcc padding bytes before the first
        # real function in the section.
        if self.is_debug:
            ofs = 0
            while True:
                (opcode, operand) = struct.unpack("<Bi", text_sect.view[ofs : ofs + 5])
                if opcode != 0xE9:
                    break

                thunk_ofs = text_start + ofs
                jmp_ofs = text_start + ofs + 5 + operand
                self.thunks.append((thunk_ofs, jmp_ofs))
                ofs += 5

        # Now check for import thunks which are present in debug and release.
        # These use an absolute JMP with the 2 byte opcode: 0xff 0x25
        idata_sections = self.get_sections_in_data_directory(
            DataDirectoryItemType.IMPORT_TABLE
        )
        ofs = text_start

        for shift in (0, 2, 4):
            window = text_sect.view[shift:]
            win_end = 6 * (len(window) // 6)
            for i, (b0, b1, jmp_ofs) in enumerate(
                struct.iter_unpack("<2BL", window[:win_end])
            ):
                if (b0, b1) == (0xFF, 0x25) and any(
                    section.contains_vaddr(jmp_ofs) for section in idata_sections
                ):
                    # Record the address of the jmp instruction and the destination in .idata
                    thunk_ofs = ofs + shift + i * 6
                    self.thunks.append((thunk_ofs, jmp_ofs))

    def _populate_exports(self, export_rva: int):
        """If you are missing a lot of annotations in your file
        (e.g. debug builds) then you can at least match up the
        export symbol names."""

        # Null = no exports
        if export_rva == 0:
            return

        export_start = self.imagebase + export_rva

        export_table = ExportDirectoryTable(
            *struct.unpack("<2L2H7L", self.read(export_start, 40))
        )

        # TODO: if the number of functions doesn't match the number of names,
        # are the remaining functions ordinals?
        n_functions = export_table.address_table_entries

        func_start = export_start + 40
        func_addrs = [
            self.imagebase + rva
            for rva, in struct.iter_unpack("<L", self.read(func_start, 4 * n_functions))
        ]

        name_start = func_start + 4 * n_functions
        name_addrs = [
            self.imagebase + rva
            for rva, in struct.iter_unpack("<L", self.read(name_start, 4 * n_functions))
        ]

        combined = zip(func_addrs, name_addrs)
        self.exports = [
            (func_addr, self.read_string(name_addr))
            for (func_addr, name_addr) in combined
        ]

    def iter_string(self, encoding: str = "ascii") -> Iterator[Tuple[int, str]]:
        """Search for possible strings at each verified address in .data."""
        section = self.get_section_by_name(".data")
        for addr in self._relocated_addrs:
            if section.contains_vaddr(addr):
                raw = self.read_string(addr)
                if raw is None:
                    continue

                try:
                    string = raw.decode(encoding)
                except UnicodeDecodeError:
                    continue

                yield (addr, string)

    def get_section_by_name(self, name: str) -> Section:
        section = next(
            filter(lambda section: section.match_name(name), self.sections),
            None,
        )

        if section is None:
            raise SectionNotFoundError

        return section

    def get_section_by_index(self, index: int) -> Section:
        """Convert 1-based index into 0-based."""
        return self.sections[index - 1]

    def get_section_extent_by_index(self, index: int) -> int:
        return self.get_section_by_index(index).extent

    def get_section_offset_by_index(self, index: int) -> int:
        """The symbols output from cvdump gives addresses in this format: AAAA.BBBBBBBB
        where A is the index (1-based) into the section table and B is the local offset.
        This will return the virtual address for the start of the section at the given index
        so you can get the virtual address for whatever symbol you are looking at.
        """
        return self.get_section_by_index(index).virtual_address

    def get_section_offset_by_name(self, name: str) -> int:
        """Same as above, but use the section name as the lookup"""

        section = self.get_section_by_name(name)
        return section.virtual_address

    def get_abs_addr(self, section: int, offset: int) -> int:
        """Convenience function for converting section:offset pairs from cvdump
        into an absolute vaddr."""
        return self.get_section_offset_by_index(section) + offset

    def get_relative_addr(self, addr: int) -> Tuple[int, int]:
        """Convert an absolute address back into a (section, offset) pair."""
        i = bisect.bisect_right(self._section_vaddr, addr) - 1
        i = max(0, i)

        section = self.sections[i]
        if section.contains_vaddr(addr):
            return (i + 1, addr - section.virtual_address)

        raise InvalidVirtualAddressError(f"{self.filename} : 0x{addr:08x} {section=}")

    def is_valid_section(self, section_id: int) -> bool:
        """The PDB will refer to sections that are not listed in the headers
        and so should ignore these references."""
        try:
            _ = self.get_section_by_index(section_id)
            return True
        except IndexError:
            return False

    def is_valid_vaddr(self, vaddr: int) -> bool:
        """Does this virtual address point to anything in the exe?"""
        try:
            (_, __) = self.get_relative_addr(vaddr)
        except InvalidVirtualAddressError:
            return False

        return True

    def read_string(self, offset: int, chunk_size: int = 1000) -> Optional[bytes]:
        """Read until we find a zero byte."""
        b = self.read(offset, chunk_size)
        if b is None:
            return None

        try:
            return b[: b.index(b"\x00")]
        except ValueError:
            # No terminator found, just return what we have
            return b

    def read(self, vaddr: int, size: int) -> Optional[bytes]:
        """Read (at most) the given number of bytes at the given virtual address.
        If we return None, the given address points to uninitialized data."""
        (section_id, offset) = self.get_relative_addr(vaddr)
        section = self.sections[section_id - 1]

        if section.addr_is_uninitialized(vaddr):
            return None

        # Clamp the read within the extent of the current section.
        # Reading off the end will most likely misrepresent the virtual addressing.
        _size = min(size, section.size_of_raw_data - offset)
        return bytes(section.view[offset : offset + _size])
