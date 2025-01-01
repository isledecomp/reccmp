"""
Based on the following resources:
- Windows SDK Headers
- PE: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Debug information: https://www.debuginfo.com/examples/src/DebugDir.cpp
"""

import dataclasses
from enum import IntEnum, IntFlag
from functools import cached_property
from pathlib import Path
import struct
from typing import Iterator, Optional

from .exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
    SectionNotFoundError,
)
from .image import Image
from .mz import ImageDosHeader

# pylint: disable=too-many-lines


class PEHeaderNotFoundError(ValueError):
    """PE magic string not found."""


class UnknownPEMachine(ValueError):
    """The PE binary has an unknown machine architecture."""


class UninitializedDataReadError(ValueError):
    """Attempt to read from an uninitialized section."""


class PEMachine(IntEnum):
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


class PECharacteristics(IntFlag):
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


# pylint: disable=too-many-instance-attributes
@dataclasses.dataclass(frozen=True)
class PEImageFileHeader:
    signature: bytes
    machine: int
    number_of_sections: int
    time_date_stamp: int
    pointer_to_symbol_table: int  # deprecated
    number_of_symbols: int  # deprecated
    size_of_optional_header: int
    characteristics: PECharacteristics

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["PEImageFileHeader", int]:
        if not cls.taste(data, offset):
            raise PEHeaderNotFoundError
        struct_fmt = "<4s2H3I2H"
        items = list(struct.unpack_from(struct_fmt, data, offset=offset))
        offset += struct.calcsize(struct_fmt)
        try:
            items[1] = PEMachine(items[1])
        except ValueError as e:
            raise UnknownPEMachine(f"0x{items[1]:x}") from e
        items[7] = PECharacteristics(items[7])
        return cls(*items), offset

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        return data[offset : offset + 4] == b"PE\x00\x00"


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


class PEDataDirectoryItemType(IntEnum):
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


@dataclasses.dataclass
class PEDataDirectoryItemHeader:
    rva: int
    virtual_size: int


@dataclasses.dataclass
class PEDataDirectoryItemRegion:
    virtual_address: int
    virtual_size: int


@dataclasses.dataclass(frozen=True)
class PEImageOptionalHeader:
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
    directories: tuple[PEDataDirectoryItemHeader, ...]

    @classmethod
    def from_memory(
        cls, data: bytes, offset: int
    ) -> tuple["PEImageOptionalHeader", int]:
        struct_fmt1 = "<H2B5I"
        part1 = struct.unpack_from(struct_fmt1, data, offset=offset)
        assert part1[0] in (0x10B, 0x20B)  # PE32, PE32+
        pe32_plus = part1[0] == 0x20B
        base_of_data = None
        struct_fmt2 = "<"
        offset += struct.calcsize(struct_fmt1)
        if not pe32_plus:
            struct_fmt2 = "<I"
            (base_of_data,) = struct.unpack_from(struct_fmt2, data, offset=offset)
        offset += struct.calcsize(struct_fmt2)
        if pe32_plus:
            struct_fmt3 = "<QII6H4I2H4Q2I"
            part3 = struct.unpack_from(struct_fmt3, data, offset=offset)
        else:
            struct_fmt3 = "<III6H4I2H4I2I"
            part3 = struct.unpack_from(struct_fmt3, data, offset=offset)
        part3 = list(part3)
        part3[13] = WindowsSubsystem(part3[13])
        part3[14] = DllCharacteristics(part3[14])
        offset += struct.calcsize(struct_fmt3)

        count_directories = part3[-1]
        directories = tuple(
            PEDataDirectoryItemHeader(*item)
            for item in struct.iter_unpack(
                "<II", data[offset : offset + 8 * count_directories]
            )
        )
        offset += 8 * count_directories
        return cls(*part1, base_of_data, *part3, directories), offset


class PESectionFlags(IntFlag):
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


@dataclasses.dataclass(frozen=True)
class PEImageSectionHeader:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    pointer_to_line_numbers: int
    number_of_relocations: int
    number_of_line_numbers: int
    characteristics: PESectionFlags

    @classmethod
    def from_memory(
        cls, data: bytes, offset: int, count: int
    ) -> tuple[tuple["PEImageSectionHeader", ...], int]:
        struct_fmt = "<8s6I2HI"
        s_size = struct.calcsize(struct_fmt)
        items = tuple(
            cls(
                members[0].decode("ascii").rstrip("\x00"),
                *members[1:-1],
                PESectionFlags(members[-1]),
            )
            for members in struct.iter_unpack(
                struct_fmt, data[offset : offset + count * s_size]
            )
        )
        return items, offset + count * struct.calcsize(struct_fmt)


@dataclasses.dataclass
class CodeViewHeaderNB10:
    cv_signature: bytes  # "NB10" (or NBxx?)
    offset: int  # always 0 for NB20
    signature: int  # seconds since 1970-01-01
    age: int  # incrementing value
    pdb_file_name: bytes  # zero terminated string with the name of the PDB file

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> Optional["CodeViewHeaderNB10"]:
        struct_fmt = "<4sIII"
        if not cls.taste(data, offset):
            raise ValueError
        items = struct.unpack_from(struct_fmt, data, offset)
        offset_pdb_filename = offset + struct.calcsize(struct_fmt)
        try:
            pos_null = data.index(0, offset_pdb_filename)
            pdb_file_name = data[offset_pdb_filename:pos_null]
        except ValueError:
            pdb_file_name = b""
        return cls(*items, pdb_file_name=pdb_file_name)

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        return data[offset : offset + 4] == b"NB10"


@dataclasses.dataclass
class CodeViewHeaderRSDS:
    cv_signature: bytes  # "RSDS"
    signature: bytes  # GUID
    pdb_file_name: bytes  # zero terminated string with the name of the PDB file

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> Optional["CodeViewHeaderRSDS"]:
        struct_fmt = "<4s16s"
        if not cls.taste(data, offset):
            raise ValueError
        items = struct.unpack_from(struct_fmt, data, offset)
        offset_pdb_filename = offset + struct.calcsize(struct_fmt)
        try:
            pos_null = data.index(0, offset_pdb_filename)
            pdb_file_name = data[offset_pdb_filename:pos_null]
        except ValueError:
            pdb_file_name = b""
        return cls(*items, pdb_file_name=pdb_file_name)

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        return data[offset : offset + 4] == b"RSDS"


@dataclasses.dataclass(frozen=True)
class PESection:
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


@dataclasses.dataclass(frozen=True)
class DebugDirectoryEntryHeader:
    characteristics: int  # Reserved, must be zero.
    time_data_stamp: int  # The time and date that the debug data was created.
    major_version: int  # The major version number of the debug data format.
    minor_version: int  # The minor version number of the debug data format.
    type: int  # The format of debugging information. This field enables support of multiple debuggers. For more information, see Debug Type.
    size_of_data: int  # The size of the debug data (not including the debug directory itself).
    address_of_raw_data: int  # The address of the debug data when loaded, relative to the image base.
    pointer_to_raw_data: int  # The file pointer to the debug data.

    @classmethod
    def from_memory(
        cls, data: bytes, offset: int
    ) -> "tuple[DebugDirectoryEntryHeader, int]":
        struct_fmt = "<2I2H4I"
        items = struct.unpack_from(struct_fmt, data, offset=offset)
        return cls(*items), offset + struct.calcsize(struct_fmt)


@dataclasses.dataclass(frozen=True)
class ExportDirectoryTable:
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


# pylint: disable=too-many-public-methods
@dataclasses.dataclass
class PEImage(Image):
    mz_header: ImageDosHeader
    header: PEImageFileHeader
    optional_header: PEImageOptionalHeader
    section_headers: tuple[PEImageSectionHeader, ...]
    sections: tuple[PESection, ...]

    # FIXME: do these belong to PEImage? Shouldn't the loade apply these to the data?
    _relocated_addrs: set[int] = dataclasses.field(default_factory=set, repr=False)
    _relocations: set[int] = dataclasses.field(default_factory=set, repr=False)
    # find_str: bool = dataclasses.field(default=False, repr=False)
    imports: list[tuple[str, str, int]] = dataclasses.field(
        default_factory=list, repr=False
    )
    exports: list[tuple[int, bytes]] = dataclasses.field(
        default_factory=list, repr=False
    )
    thunks: list[tuple[int, int]] = dataclasses.field(default_factory=list, repr=False)
    _potential_strings: dict[int, set[int]] = dataclasses.field(
        default_factory=dict, repr=False
    )

    @classmethod
    def from_memory(
        cls, data: bytes, mz_header: ImageDosHeader, filepath: Path
    ) -> "PEImage":
        offset = mz_header.e_lfanew
        view = memoryview(data)
        header, offset_optional = PEImageFileHeader.from_memory(data, offset=offset)
        optional_header, offset_sections = PEImageOptionalHeader.from_memory(
            data, offset=offset_optional
        )
        section_headers, _ = PEImageSectionHeader.from_memory(
            data, count=header.number_of_sections, offset=offset_sections
        )
        sections = tuple(
            PESection(
                name=section_header.name,
                virtual_address=optional_header.image_base
                + section_header.virtual_address,
                virtual_size=section_header.virtual_size,
                view=view[
                    section_header.pointer_to_raw_data : section_header.pointer_to_raw_data
                    + section_header.size_of_raw_data
                ],
            )
            for section_header in section_headers
        )
        image = cls(
            filepath=filepath,
            data=data,
            view=view,
            mz_header=mz_header,
            header=header,
            optional_header=optional_header,
            section_headers=section_headers,
            sections=sections,
        )
        image.load()
        image.prepare_string_search()
        return image

    def load(self):
        if self.header.machine != PEMachine.IMAGE_FILE_MACHINE_I386:
            raise ValueError(
                f"reccmp only supports i386 binaries: {self.header.machine}."
            )

        self._populate_relocations()
        self._populate_imports()
        self._populate_thunks()
        # Export dir is always first
        self._populate_exports()

        # # This is a (semi) expensive lookup that is not necessary in every case.
        # # We can find strings in the original if we have coverage using STRING markers.
        # # For the recomp, we can find strings using the PDB.
        # if self.find_str:
        #     self._prepare_string_search()

        return self

    def get_data_directory_region(
        self, t: PEDataDirectoryItemType
    ) -> Optional[PEDataDirectoryItemRegion]:
        directory_header = self.optional_header.directories[t.value]
        if not directory_header.rva:
            return None
        return PEDataDirectoryItemRegion(
            virtual_address=self.optional_header.image_base + directory_header.rva,
            virtual_size=directory_header.virtual_size,
        )

    @property
    def entry(self) -> int:
        return (
            self.optional_header.image_base
            + self.optional_header.address_of_entry_point
        )

    @property
    def is_debug(self) -> bool:
        return (
            self.optional_header.directories[PEDataDirectoryItemType.DEBUG.value].rva
            != 0
        )

    @property
    def pdb_filename(self) -> Optional[str]:
        debug_directory = self.get_data_directory_region(PEDataDirectoryItemType.DEBUG)
        if not debug_directory:
            return None
        debug_entry_data = self.read_initialized(
            debug_directory.virtual_address, debug_directory.virtual_size
        )
        offset = 0
        while offset < debug_directory.virtual_size:
            debug_entry, offset = DebugDirectoryEntryHeader.from_memory(
                debug_entry_data, offset=offset
            )
            if CodeViewHeaderNB10.taste(
                data=self.data, offset=debug_entry.pointer_to_raw_data
            ):
                cv = CodeViewHeaderNB10.from_memory(
                    data=self.data, offset=debug_entry.pointer_to_raw_data
                )
                assert cv is not None
                return cv.pdb_file_name.decode("ascii")
            if CodeViewHeaderRSDS.taste(
                data=self.data, offset=debug_entry.pointer_to_raw_data
            ):
                cv = CodeViewHeaderRSDS.from_memory(
                    data=self.data, offset=debug_entry.pointer_to_raw_data
                )
                assert cv is not None
                return cv.pdb_file_name.decode()
        return None

    @property
    def imagebase(self) -> int:
        return self.optional_header.image_base

    def get_relocated_addresses(self) -> list[int]:
        return sorted(self._relocated_addrs)

    def find_string(self, target: bytes) -> Optional[int]:
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

    def prepare_string_search(self):
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

    def get_sections_in_data_directory(
        self, t: PEDataDirectoryItemType
    ) -> list[PESection]:
        result = []
        region = self.get_data_directory_region(t)
        if region:
            for section in self.sections:
                if (
                    region.virtual_address
                    <= section.virtual_address
                    < region.virtual_address + region.virtual_size
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
            PEDataDirectoryItemType.BASE_RELOCATION_TABLE
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

    def find_float_consts(self) -> Iterator[tuple[int, int, float]]:
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
                    (float_value,) = struct.unpack(
                        "<f", self.read_initialized(const_addr, 4)
                    )
                    yield (const_addr, 4, float_value)

                elif opcode in (0xDC, 0xDD):
                    # qword ptr -- double precision
                    (float_value,) = struct.unpack(
                        "<d", self.read_initialized(const_addr, 8)
                    )
                    yield (const_addr, 8, float_value)

    def _populate_imports(self):
        """Parse .idata to find imported DLLs and their functions."""
        import_directory = self.get_data_directory_region(
            PEDataDirectoryItemType.IMPORT_TABLE
        )
        assert import_directory is not None

        def iter_image_import(offset: int):
            while True:
                # Read 5 dwords until all are zero.
                image_import_descriptor = struct.unpack(
                    "<5I", self.read_initialized(offset, 20)
                )
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

        def iter_imports() -> Iterator[tuple[str, str, int]]:
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
                    (lookup_addr,) = struct.unpack(
                        "<L", self.read_initialized(ofs_ilt, 4)
                    )
                    (import_addr,) = struct.unpack(
                        "<L", self.read_initialized(ofs_iat, 4)
                    )
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

                    yield dll_name, symbol_name, ofs_iat
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
            PEDataDirectoryItemType.IMPORT_TABLE
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

    def _populate_exports(self):
        """If you are missing a lot of annotations in your file
        (e.g. debug builds) then you can at least match up the
        export symbol names."""

        export_directory = self.get_data_directory_region(
            PEDataDirectoryItemType.EXPORT_TABLE
        )
        if not export_directory:
            return
        export_start = export_directory.virtual_address

        export_table = ExportDirectoryTable(
            *struct.unpack("<2L2H7L", self.read_initialized(export_start, 40))
        )

        # TODO: if the number of functions doesn't match the number of names,
        # are the remaining functions ordinals?
        n_functions = export_table.address_table_entries

        func_start = export_start + 40
        func_addrs: list[int] = [
            self.imagebase + rva
            for rva, in struct.iter_unpack(
                "<L", self.read_initialized(func_start, 4 * n_functions)
            )
        ]

        name_start = func_start + 4 * n_functions
        name_addrs: list[int] = [
            self.imagebase + rva
            for rva, in struct.iter_unpack(
                "<L", self.read_initialized(name_start, 4 * n_functions)
            )
        ]

        combined = zip(func_addrs, name_addrs)
        self.exports = [
            (func_addr, self.read_string(name_addr))
            for (func_addr, name_addr) in combined
        ]

    def iter_string(self, encoding: str = "ascii") -> Iterator[tuple[int, str]]:
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

                yield addr, string

    def get_section_by_name(self, name: str) -> PESection:
        try:
            return next(
                section for section in self.sections if section.match_name(name)
            )
        except StopIteration as exc:
            raise SectionNotFoundError from exc

    def get_section_by_index(self, index: int) -> PESection:
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

    @cached_property
    def vaddr_ranges(self) -> list[tuple[int, int]]:
        """Return the start and end virtual address of each section in the file."""
        return list(
            (
                self.imagebase + section.virtual_address,
                self.imagebase
                + section.virtual_address
                + max(section.size_of_raw_data, section.virtual_size),
            )
            for section in self.section_headers
        )

    def get_relative_addr(self, addr: int) -> tuple[int, int]:
        """Convert an absolute address back into a (section_id, offset) pair.
        n.b. section_id is 1-based to match PDB output."""
        for i, (start, end) in enumerate(self.vaddr_ranges):
            if start <= addr < end:
                return i + 1, addr - start

        raise InvalidVirtualAddressError(f"{self.filepath} : 0x{addr:x}")

    def is_valid_section(self, section_id: int) -> bool:
        """The PDB will refer to sections that are not listed in the headers
        and so should ignore these references."""
        try:
            _ = self.get_section_by_index(section_id)
            return True
        except IndexError:
            return False

    def is_valid_vaddr(self, vaddr: int) -> bool:
        """Is this virtual address part of the image when loaded?"""
        # Use max here just in case the section headers are not ordered by v.addr
        (_, last_vaddr) = max(self.vaddr_ranges, key=lambda s: s[1])
        return self.imagebase <= vaddr < last_vaddr

    @cached_property
    def uninitialized_ranges(self) -> list[tuple[int, int]]:
        """Return a start and end range of each region in the file that holds uninitialized data.
        This can be an entire section (.bss) or the gap between the end of the physical data
        and the virtual size. These ranges do not correspond to section ids."""
        output = []
        for section in self.section_headers:
            if (
                section.characteristics
                & PESectionFlags.IMAGE_SCN_CNT_UNINITIALIZED_DATA
            ):
                output.append(
                    (
                        self.imagebase + section.virtual_address,
                        self.imagebase + section.virtual_address + section.virtual_size,
                    )
                )
            elif section.virtual_size > section.size_of_raw_data:
                # Should also cover the case where size_of_raw_data = 0.
                output.append(
                    (
                        self.imagebase
                        + section.virtual_address
                        + section.size_of_raw_data,
                        self.imagebase + section.virtual_address + section.virtual_size,
                    )
                )

        return output

    def addr_is_uninitialized(self, vaddr: int) -> bool:
        return any(start <= vaddr < end for start, end in self.uninitialized_ranges)

    def read_string(self, vaddr: int, chunk_size: int = 1000) -> bytes:
        """Read up to chunk_size or until we find a zero byte."""
        (section_id, offset) = self.get_relative_addr(vaddr)
        section = self.sections[section_id - 1]
        view = section.view[offset : offset + chunk_size]
        # Don't call read() here because we might not get the entire chunk size.
        # Use whatever we can get if we are at the end of the section.
        return view.tobytes().partition(b"\x00")[0]

    def read(self, vaddr: int, size: int) -> bytes:
        (section_id, offset) = self.get_relative_addr(vaddr)
        section = self.sections[section_id - 1]

        # If we try to read off the end of the section
        if size < 0 or (offset + size) > section.extent:
            raise InvalidVirtualReadError(
                f"{self.filepath} : Cannot read {size} bytes from 0x{vaddr:x}"
            )

        # Pad with zero bytes if reading uninitialized data.
        # Assumes the section memoryview is cropped to the initialized bytes
        view = section.view[offset : offset + size]
        return bytes(view) + b"\x00" * (size - len(view))
