"""
Based on the following resources:
- elf.h from glibc (https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/elf.h)
"""

from dataclasses import dataclass
from enum import Enum, IntEnum
from pathlib import Path
import struct

from .image import Image


class ElfHeaderNotFoundError(ValueError):
    """Elf magic string not found."""


class Endianness(Enum):
    LITTLE = "little"
    BIG = "bit"


class ElfABI(IntEnum):
    ELFOSABI_SYSV = 0  # Alias.
    ELFOSABI_HPUX = 1  # HP-UX
    ELFOSABI_NETBSD = 2  # NetBSD.
    ELFOSABI_GNU = 3  # Object uses GNU ELF extensions.
    ELFOSABI_SOLARIS = 6  # Sun Solaris.
    ELFOSABI_AIX = 7  # IBM AIX.
    ELFOSABI_IRIX = 8  # SGI Irix.
    ELFOSABI_FREEBSD = 9  # FreeBSD.
    ELFOSABI_TRU64 = 10  # Compaq TRU64 UNIX.
    ELFOSABI_MODESTO = 11  # Novell Modesto.
    ELFOSABI_OPENBSD = 12  # OpenBSD.
    ELFOSABI_ARM_AEABI = 64  # ARM EABI
    ELFOSABI_ARM = 97  # ARM
    ELFOSABI_STANDALONE = 255  # Standalone (embedded) application */


# pylint: disable=too-many-instance-attributes
class ElfMachine(IntEnum):
    EM_NONE = 0  # No machine
    EM_M32 = 1  # AT&T WE 32100
    EM_SPARC = 2  # SUN SPARC
    EM_386 = 3  # Intel 80386
    EM_68K = 4  # Motorola m68k family
    EM_88K = 5  # Motorola m88k family
    EM_IAMCU = 6  # Intel MCU
    EM_860 = 7  # Intel 80860
    EM_MIPS = 8  # MIPS R3000 big-endian
    EM_S370 = 9  # IBM System/370
    EM_MIPS_RS3_LE = 10  # MIPS R3000 little-endian
    EM_PARISC = 15  # HPPA
    EM_VPP500 = 17  # Fujitsu VPP500
    EM_SPARC32PLUS = 18  # Sun's "v8plus"
    EM_960 = 19  # Intel 80960
    EM_PPC = 20  # PowerPC
    EM_PPC64 = 21  # PowerPC 64-bit
    EM_S390 = 22  # IBM S390
    EM_SPU = 23  # IBM SPU/SPC
    EM_V800 = 36  # NEC V800 series
    EM_FR20 = 37  # Fujitsu FR20
    EM_RH32 = 38  # TRW RH-32
    EM_RCE = 39  # Motorola RCE
    EM_ARM = 40  # ARM
    EM_FAKE_ALPHA = 41  # Digital Alpha
    EM_SH = 42  # Hitachi SH
    EM_SPARCV9 = 43  # SPARC v9 64-bit
    EM_TRICORE = 44  # Siemens Tricore
    EM_ARC = 45  # Argonaut RISC Core
    EM_H8_300 = 46  # Hitachi H8/300
    EM_H8_300H = 47  # Hitachi H8/300H
    EM_H8S = 48  # Hitachi H8S
    EM_H8_500 = 49  # Hitachi H8/500
    EM_IA_64 = 50  # Intel Merced
    EM_MIPS_X = 51  # Stanford MIPS-X
    EM_COLDFIRE = 52  # Motorola Coldfire
    EM_68HC12 = 53  # Motorola M68HC12
    EM_MMA = 54  # Fujitsu MMA Multimedia Accelerator
    EM_PCP = 55  # Siemens PCP
    EM_NCPU = 56  # Sony nCPU embedded RISC
    EM_NDR1 = 57  # Denso NDR1 microprocessor
    EM_STARCORE = 58  # Motorola Start*Core processor
    EM_ME16 = 59  # Toyota ME16 processor
    EM_ST100 = 60  # STMicroelectronic ST100 processor
    EM_TINYJ = 61  # Advanced Logic Corp. Tinyj emb.fam
    EM_X86_64 = 62  # AMD x86-64 architecture
    EM_PDSP = 63  # Sony DSP Processor
    EM_PDP10 = 64  # Digital PDP-10
    EM_PDP11 = 65  # Digital PDP-11
    EM_FX66 = 66  # Siemens FX66 microcontroller
    EM_ST9PLUS = 67  # STMicroelectronics ST9+ 8/16 mc
    EM_ST7 = 68  # STmicroelectronics ST7 8 bit mc
    EM_68HC16 = 69  # Motorola MC68HC16 microcontroller
    EM_68HC11 = 70  # Motorola MC68HC11 microcontroller
    EM_68HC08 = 71  # Motorola MC68HC08 microcontroller
    EM_68HC05 = 72  # Motorola MC68HC05 microcontroller
    EM_SVX = 73  # Silicon Graphics SVx
    EM_ST19 = 74  # STMicroelectronics ST19 8 bit mc
    EM_VAX = 75  # Digital VAX
    EM_CRIS = 76  # Axis Communications 32-bit emb.proc
    EM_JAVELIN = 77  # Infineon Technologies 32-bit emb.proc
    EM_FIREPATH = 78  # Element 14 64-bit DSP Processor
    EM_ZSP = 79  # LSI Logic 16-bit DSP Processor
    EM_MMIX = 80  # Donald Knuth's educational 64-bit proc
    EM_HUANY = 81  # Harvard University machine-independent object files
    EM_PRISM = 82  # SiTera Prism
    EM_AVR = 83  # Atmel AVR 8-bit microcontroller
    EM_FR30 = 84  # Fujitsu FR30
    EM_D10V = 85  # Mitsubishi D10V
    EM_D30V = 86  # Mitsubishi D30V
    EM_V850 = 87  # NEC v850
    EM_M32R = 88  # Mitsubishi M32R
    EM_MN10300 = 89  # Matsushita MN10300
    EM_MN10200 = 90  # Matsushita MN10200
    EM_PJ = 91  # picoJava
    EM_OPENRISC = 92  # OpenRISC 32-bit embedded processor
    EM_ARC_COMPACT = 93  # ARC International ARCompact
    EM_XTENSA = 94  # Tensilica Xtensa Architecture
    EM_VIDEOCORE = 95  # Alphamosaic VideoCore
    EM_TMM_GPP = 96  # Thompson Multimedia General Purpose Proc
    EM_NS32K = 97  # National Semi. 32000
    EM_TPC = 98  # Tenor Network TPC
    EM_SNP1K = 99  # Trebia SNP 1000
    EM_ST200 = 100  # STMicroelectronics ST200
    EM_IP2K = 101  # Ubicom IP2xxx
    EM_MAX = 102  # MAX processor
    EM_CR = 103  # National Semi. CompactRISC
    EM_F2MC16 = 104  # Fujitsu F2MC16
    EM_MSP430 = 105  # Texas Instruments msp430
    EM_BLACKFIN = 106  # Analog Devices Blackfin DSP
    EM_SE_C33 = 107  # Seiko Epson S1C33 family
    EM_SEP = 108  # Sharp embedded microprocessor
    EM_ARCA = 109  # Arca RISC
    EM_UNICORE = 110  # PKU-Unity & MPRC Peking Uni. mc series
    EM_EXCESS = 111  # eXcess configurable cpu
    EM_DXP = 112  # Icera Semi. Deep Execution Processor
    EM_ALTERA_NIOS2 = 113  # Altera Nios II
    EM_CRX = 114  # National Semi. CompactRISC CRX
    EM_XGATE = 115  # Motorola XGATE
    EM_C166 = 116  # Infineon C16x/XC16x
    EM_M16C = 117  # Renesas M16C
    EM_DSPIC30F = 118  # Microchip Technology dsPIC30F
    EM_CE = 119  # Freescale Communication Engine RISC
    EM_M32C = 120  # Renesas M32C
    EM_TSK3000 = 131  # Altium TSK3000
    EM_RS08 = 132  # Freescale RS08
    EM_SHARC = 133  # Analog Devices SHARC family
    EM_ECOG2 = 134  # Cyan Technology eCOG2
    EM_SCORE7 = 135  # Sunplus S+core7 RISC
    EM_DSP24 = 136  # New Japan Radio (NJR) 24-bit DSP
    EM_VIDEOCORE3 = 137  # Broadcom VideoCore III
    EM_LATTICEMICO32 = 138  # RISC for Lattice FPGA
    EM_SE_C17 = 139  # Seiko Epson C17
    EM_TI_C6000 = 140  # Texas Instruments TMS320C6000 DSP
    EM_TI_C2000 = 141  # Texas Instruments TMS320C2000 DSP
    EM_TI_C5500 = 142  # Texas Instruments TMS320C55x DSP
    EM_TI_ARP32 = 143  # Texas Instruments App. Specific RISC
    EM_TI_PRU = 144  # Texas Instruments Prog. Realtime Unit
    EM_MMDSP_PLUS = 160  # STMicroelectronics 64bit VLIW DSP
    EM_CYPRESS_M8C = 161  # Cypress M8C
    EM_R32C = 162  # Renesas R32C
    EM_TRIMEDIA = 163  # NXP Semi. TriMedia
    EM_QDSP6 = 164  # QUALCOMM DSP6
    EM_8051 = 165  # Intel 8051 and variants
    EM_STXP7X = 166  # STMicroelectronics STxP7x
    EM_NDS32 = 167  # Andes Tech. compact code emb. RISC
    EM_ECOG1X = 168  # Cyan Technology eCOG1X
    EM_MAXQ30 = 169  # Dallas Semi. MAXQ30 mc
    EM_XIMO16 = 170  # New Japan Radio (NJR) 16-bit DSP
    EM_MANIK = 171  # M2000 Reconfigurable RISC
    EM_CRAYNV2 = 172  # Cray NV2 vector architecture
    EM_RX = 173  # Renesas RX
    EM_METAG = 174  # Imagination Tech. META
    EM_MCST_ELBRUS = 175  # MCST Elbrus
    EM_ECOG16 = 176  # Cyan Technology eCOG16
    EM_CR16 = 177  # National Semi. CompactRISC CR16
    EM_ETPU = 178  # Freescale Extended Time Processing Unit
    EM_SLE9X = 179  # Infineon Tech. SLE9X
    EM_L10M = 180  # Intel L10M
    EM_K10M = 181  # Intel K10M
    EM_AARCH64 = 183  # ARM AARCH64
    EM_AVR32 = 185  # Amtel 32-bit microprocessor
    EM_STM8 = 186  # STMicroelectronics STM8
    EM_TILE64 = 187  # Tilera TILE64
    EM_TILEPRO = 188  # Tilera TILEPro
    EM_MICROBLAZE = 189  # Xilinx MicroBlaze
    EM_CUDA = 190  # NVIDIA CUDA
    EM_TILEGX = 191  # Tilera TILE-Gx
    EM_CLOUDSHIELD = 192  # CloudShield
    EM_COREA_1ST = 193  # KIPO-KAIST Core-A 1st gen.
    EM_COREA_2ND = 194  # KIPO-KAIST Core-A 2nd gen.
    EM_ARCV2 = 195  # Synopsys ARCv2 ISA.
    EM_OPEN8 = 196  # Open8 RISC
    EM_RL78 = 197  # Renesas RL78
    EM_VIDEOCORE5 = 198  # Broadcom VideoCore V
    EM_78KOR = 199  # Renesas 78KOR
    EM_56800EX = 200  # Freescale 56800EX DSC
    EM_BA1 = 201  # Beyond BA1
    EM_BA2 = 202  # Beyond BA2
    EM_XCORE = 203  # XMOS xCORE
    EM_MCHP_PIC = 204  # Microchip 8-bit PIC(r)
    EM_INTELGT = 205  # Intel Graphics Technology
    EM_KM32 = 210  # KM211 KM32
    EM_KMX32 = 211  # KM211 KMX32
    EM_EMX16 = 212  # KM211 KMX16
    EM_EMX8 = 213  # KM211 KMX8
    EM_KVARC = 214  # KM211 KVARC
    EM_CDP = 215  # Paneve CDP
    EM_COGE = 216  # Cognitive Smart Memory Processor
    EM_COOL = 217  # Bluechip CoolEngine
    EM_NORC = 218  # Nanoradio Optimized RISC
    EM_CSR_KALIMBA = 219  # CSR Kalimba
    EM_Z80 = 220  # Zilog Z80
    EM_VISIUM = 221  # Controls and Data Services VISIUMcore
    EM_FT32 = 222  # FTDI Chip FT32
    EM_MOXIE = 223  # Moxie processor
    EM_AMDGPU = 224  # AMD GPU
    EM_RISCV = 243  # RISC-V
    EM_BPF = 247  # Linux BPF -- in-kernel virtual machine
    EM_CSKY = 252  # C-SKY
    EM_LOONGARCH = 258  # LoongArch


@dataclass(frozen=True)
class ElfFileHeader:
    e_ident: bytes  # Magic number and other info
    e_type: int  # Object file type
    e_machine: ElfMachine  # Architecture
    e_version: int  # Object file version
    e_entry: int  # Entry point virtual address
    e_phoff: int  # Program header table file offset
    e_shoff: int  # Section header table file offset
    e_flags: int  # Processor-specific flags
    e_ehsize: int  # ELF header size in bytes
    e_phentsize: int  # Program header table entry size
    e_phnum: int  # Program header table entry count
    e_shentsize: int  # Section header table entry size
    e_shnum: int  # Section header table entry count
    e_shstrndx: int  # Section header string table index

    @property
    def bitness(self) -> int:
        if self.e_ident[4] == 1:
            return 32
        if self.e_ident[4] == 2:
            return 64
        raise ValueError(self.e_ident[4])

    @property
    def endianess(self) -> Endianness:
        if self.e_ident[5] == b"\x01":
            return Endianness.LITTLE
        if self.e_ident[5] == b"\x02":
            return Endianness.BIG
        raise ValueError(self.e_ident[5])

    @property
    def abi(self) -> ElfABI:
        return ElfABI(self.e_ident[7])

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["ElfFileHeader", int]:
        ident = data[offset : offset + 16]
        if not cls.taste(data, offset=offset):
            raise ElfHeaderNotFoundError
        match ord(bytes(ident[4:5])):
            case 1:
                struct_fmt_pt2 = "16sHHIIIIIHHHHHH"  # 32-bit
            case 2:
                struct_fmt_pt2 = "16sHHIQQQIHHHHHH"  # 64-bit
            case _:
                raise ValueError("Invalid file class")
        match ord(bytes(ident[5:6])):
            case 1:
                struct_fmt_pt1 = "<"  # little endian
            case 2:
                struct_fmt_pt1 = ">"  # bit endian
            case _:
                raise ValueError("Invalid endianness")
        struct_fmt = struct_fmt_pt1 + struct_fmt_pt2
        items = struct.unpack_from(struct_fmt, data, offset=offset)
        return cls(*items[:2], ElfMachine(items[2]), *items[3:]), struct.calcsize(
            struct_fmt
        )

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        return bytes(data[offset : offset + 4]) == b"\x7fELF"


@dataclass
class ElfImage(Image):
    header: ElfFileHeader

    @classmethod
    def from_memory(cls, data: bytes, offset: int, filepath: Path) -> "ElfImage":
        header, _ = ElfFileHeader.from_memory(data, offset=offset)
        return cls(filepath=filepath, data=data, view=memoryview(data), header=header)

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        return ElfFileHeader.taste(data, offset=offset)
