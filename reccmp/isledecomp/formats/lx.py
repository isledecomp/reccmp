""""
Based on the following resources:
- LX - Linear eXecutable Module Format Description (http://www.edm2.com/index.php/LX_-_Linear_eXecutable_Module_Format_Description)
"""

import struct
from dataclasses import dataclass
from pathlib import Path

from .image import Image
from .mz import ImageDosHeader


class LXHeaderNotFoundError(ValueError):
    pass


# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class LXImageHeader:
    magic: bytes
    byte_ordering: int
    word_ordering: int
    format_level: int
    cpu_type: int
    os_type: int
    module_version: int
    module_flags: int
    module_number_of_pages: int
    eip_object_nb: int
    eip: int
    esp_object_nb: int
    esp: int
    page_size: int
    page_offset_shift: int
    fixup_section_size: int
    fixup_section_checksum: int
    loader_section_size: int
    loader_section_checksum: int
    object_table_off: int
    nb_objects_in_module: int
    object_page_table_offset: int
    object_iter_pages_off: int
    resource_table_off: int
    nb_resource_table_entries: int
    resident_name_table_offset: int
    entry_table_offset: int
    module_directives_offset: int
    nb_module_directives: int
    fixup_page_table_offset: int
    fixup_record_table_offset: int
    import_module_table_offset: int
    nb_import_module_entries: int
    import_procedure_table_offset: int
    per_page_checksum_offset: int
    data_pages_offset: int
    nb_preload_pages: int
    non_resident_name_table_offset: int
    non_resident_name_table_length: int
    non_resident_name_table_checksum: int
    auto_ds_object_nb: int
    debug_info_offset: int
    debug_info_len: int
    nb_instance_preload: int
    nb_instance_demand: int
    heap_size: int

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["LXImageHeader", int]:
        if not cls.taste(data, offset):
            raise LXHeaderNotFoundError
        if data[offset + 2] != 0 or data[offset + 3] != 0:
            raise NotImplementedError("Big-endian LX not implemented")
        struct_fmt = "<2s2BI2H40I"
        items = struct.unpack_from(struct_fmt, data, offset)
        return cls(*items), offset + struct.calcsize(struct_fmt)

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        return data[offset : offset + 2] == b"LE"


@dataclass
class LXImage(Image):
    mz_header: ImageDosHeader
    header: LXImageHeader

    @classmethod
    def from_memory(
        cls, data: bytes, mz_header: ImageDosHeader, filepath: Path
    ) -> "LXImage":
        offset = mz_header.e_lfanew
        header, _ = LXImageHeader.from_memory(data, offset)
        return cls(
            filepath=filepath,
            data=data,
            view=memoryview(data),
            mz_header=mz_header,
            header=header,
        )
