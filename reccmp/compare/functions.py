from dataclasses import dataclass, field
from functools import cache
import struct
from itertools import pairwise
from typing import Callable, Iterator
from reccmp.compare.lines import LinesDb
from reccmp.compare.pinned_sequences import SequenceMatcherWithPins
from reccmp.compare.asm.effective import CallAbi, FunctionMetadata
from reccmp.compare.asm.fixes import assert_fixup, find_effective_match
from reccmp.compare.asm.parse import AsmExcerpt, ParseAsm
from reccmp.compare.asm.replacement import (
    create_name_lookup,
)
from reccmp.compare.db import EntityDb, ReccmpMatch
from reccmp.compare.diff import EntityCompareResult, RawDiffOutput
from reccmp.compare.event import ReccmpEvent, ReccmpReportProtocol
from reccmp.cvdump.analysis import CvdumpNode
from reccmp.cvdump.cvinfo import CvdumpTypeKey, CvdumpTypeMap
from reccmp.cvdump.demangler import parse_function_signature
from reccmp.cvdump.types import CvdumpKeyError, CvdumpTypesParser
from reccmp.types import EntityType
from reccmp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.formats import Image, PEImage
from reccmp.types import ImageId

# Register-argument usage by PDB calling convention. cdecl and stdcall
# take all arguments on the stack; thiscall reads the receiver from ecx;
# fastcall reads its first two register-sized arguments from ecx and edx.
_CALL_ABI_BY_CONVENTION = {
    "C Near": CallAbi(uses_ecx=False, uses_edx=False),
    "STD Near": CallAbi(uses_ecx=False, uses_edx=False),
    "ThisCall": CallAbi(uses_ecx=True, uses_edx=False),
    "Fast Near": CallAbi(uses_ecx=True, uses_edx=True),
    # Conventions as recovered from decorated names.
    "cdecl": CallAbi(uses_ecx=False, uses_edx=False),
    "stdcall": CallAbi(uses_ecx=False, uses_edx=False),
    "thiscall": CallAbi(uses_ecx=True, uses_edx=False),
    "fastcall": CallAbi(uses_ecx=True, uses_edx=True),
}

_RETURN_KIND_BY_SIZE = {1: "i8", 2: "i16", 4: "i32", 8: "i64"}


def has_asserts(image: Image) -> bool:
    if isinstance(image, PEImage):
        return image.is_debug

    return False


def create_valid_addr_lookup(
    db: EntityDb,
    image_id: ImageId,
    bin_file: Image,
) -> Callable[[int], bool]:
    """
    Function generator for a lookup whether an address from a call is valid
    (either a relocation or pointing to something else we know, like a global variable)
    """
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    @cache
    def lookup(addr: int) -> bool:
        # Check if in relocation table
        if addr > bin_file.imagebase and bin_file.is_relocated_addr(addr):
            return True

        return db.intersects(image_id, addr)

    return lookup


def create_bin_lookup(bin_file: Image) -> Callable[[int], int | None]:
    """Function generator to read a pointer from the bin file"""

    def lookup(addr: int) -> int | None:
        try:
            (ptr,) = struct.unpack("<L", bin_file.read(addr, 4))
            return ptr
        except (struct.error, InvalidVirtualAddressError, InvalidVirtualReadError):
            return None

    return lookup


@dataclass
class FunctionComparator:
    # pylint: disable=too-many-instance-attributes
    db: EntityDb
    lines_db: LinesDb
    orig_bin: Image
    recomp_bin: Image
    report: ReccmpReportProtocol
    types: CvdumpTypesParser
    is_32bit: bool = True
    # PDB function nodes keyed by recomp address, used to derive return
    # kinds and callee register-argument conventions for the effective-match
    # verifier. Optional: without it the verifier stays fully conservative.
    func_nodes: dict[int, CvdumpNode] = field(default_factory=dict)

    def __post_init__(self):
        self._call_abi_cache: dict[str, CallAbi | None] | None = None
        self.orig_sanitize = ParseAsm(
            addr_test=create_valid_addr_lookup(self.db, ImageId.ORIG, self.orig_bin),
            name_lookup=create_name_lookup(
                self.db,
                ImageId.ORIG,
                create_bin_lookup(self.orig_bin),
                self.types.get_name_for_offset,
            ),
            is_32bit=self.is_32bit,
        )
        self.recomp_sanitize = ParseAsm(
            addr_test=create_valid_addr_lookup(
                self.db, ImageId.RECOMP, self.recomp_bin
            ),
            name_lookup=create_name_lookup(
                self.db,
                ImageId.RECOMP,
                create_bin_lookup(self.recomp_bin),
                self.types.get_name_for_offset,
            ),
            is_32bit=self.is_32bit,
        )

    def _source_ref_of_recomp_addr(self, recomp_addr: int | None) -> str | None:
        if recomp_addr is None:
            return None
        path_line_pair = self.lines_db.find_line_of_recomp_address(recomp_addr)
        if path_line_pair is None:
            return None
        return f"{path_line_pair[0].name}:{path_line_pair[1]}"

    def compare_function(self, match: ReccmpMatch) -> EntityCompareResult:
        # Detect when the recomp function size would cause us to read
        # enough bytes from the original function that we cross into
        # the next annotated function.
        orig_size = match.size(ImageId.ORIG)
        recomp_size = match.size(ImageId.RECOMP)

        if orig_size is None:
            assert recomp_size is not None
            orig_max = match.max_size(ImageId.ORIG)
            if orig_max is not None:
                orig_size = min(orig_max, recomp_size)
            else:
                orig_size = recomp_size

        assert orig_size is not None and recomp_size is not None

        orig_raw = self.orig_bin.read(match.orig_addr, orig_size)
        recomp_raw = self.recomp_bin.read(match.recomp_addr, recomp_size)

        # It's unlikely that a function other than an adjuster thunk would
        # start with a SUB instruction, so alert to a possible wrong
        # annotation here.
        # There's probably a better place to do this, but we're reading
        # the function bytes here already.
        try:
            if orig_raw[0] == 0x2B and recomp_raw[0] != 0x2B:
                self.report(
                    ReccmpEvent.GENERAL_WARNING,
                    match.orig_addr,
                    f"Possible thunk ({match.name})",
                )
        except IndexError:
            pass

        orig_combined = self.orig_sanitize.parse_asm(orig_raw, match.orig_addr)
        recomp_combined = self.recomp_sanitize.parse_asm(recomp_raw, match.recomp_addr)

        # Check for assert calls only if we expect to find them
        if has_asserts(self.orig_bin):
            assert_fixup(orig_combined)

        if has_asserts(self.recomp_bin):
            assert_fixup(recomp_combined)

        line_annotations = self._collect_line_annotations(recomp_combined)

        split_points = self._compute_split_points(
            orig_combined, recomp_combined, line_annotations
        )

        return self._compare_function_assembly(
            orig_combined,
            recomp_combined,
            split_points,
            self._function_metadata(match),
        )

    # ------------------------------------------------------------------
    # PDB-derived metadata for the effective-match verifier

    def _return_kind_of_type(self, type_key: CvdumpTypeKey) -> str:
        # pylint: disable=too-many-return-statements
        """Reduce a PDB return type to the register footprint of the
        returned value. Unknown or by-value aggregate returns stay
        "unknown", which makes the verifier compare eax exactly."""
        for _ in range(8):
            if type_key.is_scalar():
                scalar = CvdumpTypeMap.get(type_key)
                if scalar is None:
                    return "unknown"
                if scalar.name == "T_VOID":
                    return "void"
                if scalar.pointer is not None:
                    return "i32"
                if scalar.name.startswith("T_REAL"):
                    return "float"
                return _RETURN_KIND_BY_SIZE.get(scalar.size, "unknown")
            try:
                obj = self.types.from_key(type_key)
            except CvdumpKeyError:
                return "unknown"
            leaf = obj.get("type")
            if leaf == "LF_POINTER":
                return "i32"
            if leaf == "LF_ENUM" and "underlying_type" in obj:
                type_key = obj["underlying_type"]
                continue
            if leaf == "LF_MODIFIER" and "modifies" in obj:
                type_key = obj["modifies"]
                continue
            return "unknown"
        return "unknown"

    def _signature_of_node(self, node: CvdumpNode) -> tuple[str, CallAbi | None]:
        """(return kind, register-argument ABI) for one function node.
        Prefers the PDB TYPES record; falls back to the decorated name,
        which encodes the convention and return type even when the PDB
        (like Imperialism's) carries no type records at all."""
        return_kind = "unknown"
        abi = None
        if node.symbol_entry is not None:
            try:
                func = self.types.from_key(node.symbol_entry.func_type)
                abi = _CALL_ABI_BY_CONVENTION.get(func.get("call_type", ""))
                if "return_type" in func:
                    return_kind = self._return_kind_of_type(func["return_type"])
            except CvdumpKeyError:
                pass
        if (return_kind == "unknown" or abi is None) and node.decorated_name:
            mangled = parse_function_signature(node.decorated_name)
            if return_kind == "unknown":
                return_kind = mangled.return_kind
            if abi is None and mangled.convention is not None:
                abi = _CALL_ABI_BY_CONVENTION.get(mangled.convention)
        return (return_kind, abi)

    def _call_abi_map(self) -> dict[str, CallAbi | None]:
        """Map from a sanitized call-target name (as the diff displays it)
        to the callee's register-argument usage. A name shared by several
        functions with conflicting conventions resolves to None (unknown)."""
        if self._call_abi_cache is not None:
            return self._call_abi_cache
        result: dict[str, CallAbi | None] = {}
        for entity in self.db.get_all():
            if entity.entity_type != EntityType.FUNCTION:
                continue
            recomp_addr = entity.recomp_addr
            if recomp_addr is None:
                continue
            node = self.func_nodes.get(recomp_addr)
            if node is None:
                continue
            name = entity.match_name()
            if name is None:
                continue
            _, abi = self._signature_of_node(node)
            if name in result and result[name] != abi:
                result[name] = None
            else:
                result[name] = abi
        self._call_abi_cache = result
        return result

    def _function_metadata(self, match: ReccmpMatch) -> FunctionMetadata | None:
        if not self.func_nodes:
            return None
        return_kind = "unknown"
        node = self.func_nodes.get(match.recomp_addr)
        if node is not None:
            return_kind, _ = self._signature_of_node(node)
        abi_map = self._call_abi_map()
        return FunctionMetadata(
            return_kind=return_kind,
            call_abi=abi_map.get,
        )

    @staticmethod
    def _print_recomp_instruction(
        instruction: str, *, source_ref: str | None, is_pinned: bool
    ) -> str:
        match source_ref, is_pinned:
            case None, _:
                # cannot be pinned if it has no source reference
                return instruction
            case source_ref_str, False:
                return f"{instruction} \t({source_ref_str})"
            case source_ref_str, True:
                return f"{instruction} \t({source_ref_str}, pinned)"
            case _:
                # Unreachable, but mypy doesn't understand
                assert False

    def _compare_function_assembly(
        self,
        orig: AsmExcerpt,
        recomp: AsmExcerpt,
        split_points: list[tuple[int, int]],
        metadata: FunctionMetadata | None = None,
    ) -> EntityCompareResult:
        # Detach addresses from asm lines for the text diff.
        orig_asm = [x[1] for x in orig]
        recomp_asm = [x[1] for x in recomp]

        diff = SequenceMatcherWithPins(orig_asm, recomp_asm, split_points)

        if diff.ratio() != 1.0:
            # Check whether we can resolve register swaps which are actually
            # perfect matches modulo compiler entropy.
            is_effective = find_effective_match(
                diff.get_opcodes(),
                orig_asm,
                recomp_asm,
                orig_addrs=[x[0] for x in orig],
                metadata=metadata,
            )
        else:
            is_effective = False

        # Convert the addresses to hex string for the diff output
        orig_for_printing = [
            (hex(addr) if addr is not None else "", instr) for addr, instr in orig
        ]

        recomp_for_printing = [
            (
                hex(addr) if addr is not None else "",
                self._print_recomp_instruction(
                    instruction,
                    source_ref=self._source_ref_of_recomp_addr(addr),
                    is_pinned=any(
                        recomp_addr == line_index for _, recomp_addr in split_points
                    ),
                ),
            )
            for line_index, (addr, instruction) in enumerate(recomp)
        ]

        return EntityCompareResult(
            diff=RawDiffOutput(
                codes=diff.get_opcodes(),
                orig_inst=orig_for_printing,
                recomp_inst=recomp_for_printing,
            ),
            is_effective_match=is_effective,
            match_ratio=diff.ratio(),
        )

    def _collect_line_annotations(self, recomp: AsmExcerpt) -> list[ReccmpMatch]:
        """
        Finds all `// LINE:` annotations within the given function
        and drops any whose order is not consistent between original and recomp.
        """
        if len(recomp) == 0:
            return []

        recomp_start_addr = recomp[0][0]
        recomp_end_addr = recomp[-1][0]
        assert recomp_start_addr is not None and recomp_end_addr is not None
        line_annotations = self.db.get_lines_in_recomp_range(
            recomp_start_addr, recomp_end_addr
        )

        # This is a naive/greedy algorithm to remove the non-monotonous entries.
        # There likely is a "better" way to do this, in the sense that the smallest number
        # of entries is removed.
        line_annotations_monotonous: list[ReccmpMatch] = []
        last_address = 0
        for sync_point in line_annotations:
            if sync_point.recomp_addr > last_address:
                line_annotations_monotonous.append(sync_point)
                last_address = sync_point.recomp_addr
            else:
                self.report(
                    ReccmpEvent.WRONG_ORDER,
                    sync_point.orig_addr,
                    f"Line annotation '{sync_point.name}' is out of order relative to other line annotations.",
                )

        return line_annotations_monotonous

    def _split_code_on_line_annotations(
        self,
        orig_combined: AsmExcerpt,
        recomp_combined: AsmExcerpt,
        line_annotations: list[ReccmpMatch],
    ) -> Iterator[tuple[AsmExcerpt, AsmExcerpt]]:
        """
        For each given `// LINE:` annotation, splits the code into the part before,
        the annotated line, and the part after it.
        """
        split_points = self._compute_split_points(
            orig_combined, recomp_combined, line_annotations
        )

        for (orig_start, recomp_start), (orig_end, recomp_end) in pairwise(
            split_points
        ):
            yield (
                orig_combined[orig_start:orig_end],
                recomp_combined[recomp_start:recomp_end],
            )

    def _compute_split_points(
        self, orig: AsmExcerpt, recomp: AsmExcerpt, line_annotations: list[ReccmpMatch]
    ) -> list[tuple[int, int]]:
        """
        Computes the index pairs into `orig` and `recomp`
        that correspond to the line annotations given in `line_annotations`.
        """
        split_points: list[tuple[int, int]] = []

        for line_annotation in line_annotations:
            orig_split_index = next(
                (
                    i
                    for i, entry in enumerate(orig)
                    if entry[0] == line_annotation.orig_addr
                ),
                None,
            )
            if orig_split_index is None:
                self.report(
                    ReccmpEvent.NO_MATCH,
                    line_annotation.orig_addr,
                    "Found no code line corresponding to this original address",
                )
                continue

            recomp_split_index = next(
                (
                    i
                    for i, entry in enumerate(recomp)
                    if entry[0] == line_annotation.recomp_addr
                ),
                None,
            )
            if recomp_split_index is None:
                self.report(
                    ReccmpEvent.NO_MATCH,
                    line_annotation.orig_addr,
                    f"Found no code line corresponding to recomp address {hex(line_annotation.recomp_addr)}. Recompilation may fix this problem.",
                )
                continue

            split_points.append((orig_split_index, recomp_split_index))
            split_points.append((orig_split_index + 1, recomp_split_index + 1))

        return split_points
