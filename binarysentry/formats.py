"""Binary format detection and header parsing.

Everything here works on bytes. There is no dependency on ``pefile`` or ``pyelftools``
because the interesting part of a supply-chain inspection tool is that it agrees with
the spec rather than with a library's convenience wrappers, and because a parser that
has to survive hostile input should be small enough to reason about.

All readers treat the input as untrusted: every offset is bounds-checked, every
length is capped, and a truncated file produces a partial result plus a warning
instead of an exception.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "Format",
    "BinaryInfo",
    "Section",
    "Import",
    "detect",
    "parse",
    "BinaryParseError",
]


class BinaryParseError(ValueError):
    """Raised only when the input is so malformed that nothing can be said about it."""


class Format(str, Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    FAT = "fat"
    SCRIPT = "script"
    ARCHIVE = "archive"
    UNKNOWN = "unknown"


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float = 0.0
    executable: bool = False
    writable: bool = False

    @property
    def is_packed_indicator(self) -> bool:
        """High entropy in an executable section suggests compression or encryption.

        7.2 bits/byte is the usual threshold: ordinary code sits near 6.2-6.6, and
        compressed data sits above 7.4.
        """
        return self.executable and self.entropy >= 7.2 and self.raw_size > 512


@dataclass
class Import:
    library: str
    symbols: list[str] = field(default_factory=list)


@dataclass
class BinaryInfo:
    fmt: Format
    arch: str = ""
    bits: int = 0
    endian: str = ""
    entry_point: int = 0
    sections: list[Section] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Format-specific extras kept out of the typed fields.
    metadata: dict = field(default_factory=dict)

    @property
    def high_entropy_sections(self) -> list[Section]:
        return [s for s in self.sections if s.is_packed_indicator]

    def to_dict(self) -> dict:
        return {
            "format": self.fmt.value,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "entry_point": f"0x{self.entry_point:x}" if self.entry_point else "",
            "sections": [
                {
                    "name": s.name,
                    "vaddr": f"0x{s.virtual_address:x}",
                    "vsize": s.virtual_size,
                    "raw_size": s.raw_size,
                    "entropy": round(s.entropy, 2),
                    "executable": s.executable,
                    "writable": s.writable,
                }
                for s in self.sections
            ],
            "imports": [
                {"library": i.library, "symbol_count": len(i.symbols)}
                for i in self.imports
            ],
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


# --- entropy -----------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte, 0..8."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    import math

    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


# --- detection ---------------------------------------------------------------

_MACHO_MAGICS = {
    # Keys are the magic read big-endian. On disk a little-endian file stores the
    # bytes reversed, so it reads back as the byte-swapped (CIGAM) constant.
    0xFEEDFACE: (32, "big"),
    0xFEEDFACF: (64, "big"),
    0xCEFAEDFE: (32, "little"),
    0xCFFAEDFE: (64, "little"),
}


def detect(data: bytes) -> Format:
    """Identify the container format from the first bytes.

    Order matters: a fat Mach-O also starts with a valid magic, and a zip archive is
    also a jar and a wheel, so the most specific signature wins.
    """
    if len(data) < 4:
        return Format.UNKNOWN

    if data[:2] == b"MZ":
        # MZ alone is a DOS executable; the PE signature lives at e_lfanew.
        if len(data) >= 0x40:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if 0 <= e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\0\0":
                return Format.PE
        return Format.UNKNOWN

    if data[:4] == b"\x7fELF":
        return Format.ELF

    magic_be = struct.unpack_from(">I", data, 0)[0]
    magic_le = struct.unpack_from("<I", data, 0)[0]
    if magic_be in _MACHO_MAGICS or magic_le in _MACHO_MAGICS:
        return Format.MACHO
    if magic_be in (0xCAFEBABE, 0xCAFEBABF):
        # 0xCAFEBABE is shared with Java class files; those are followed by a version
        # word, while fat binaries are followed by a plausibly small slice count.
        if len(data) >= 8:
            n = struct.unpack_from(">I", data, 4)[0]
            if 1 <= n <= 20:
                return Format.FAT
        return Format.UNKNOWN

    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return Format.ARCHIVE
    if data[:8] == b"!<arch>\n":
        return Format.ARCHIVE

    head = data[:256].lstrip()
    for shebang in (b"#!/", b"#! "):
        if head.startswith(shebang):
            return Format.SCRIPT

    return Format.UNKNOWN


def parse(data: bytes) -> BinaryInfo:
    """Detect and parse in one step."""
    fmt = detect(data)
    if fmt is Format.PE:
        return _parse_pe(data)
    if fmt is Format.ELF:
        return _parse_elf(data)
    if fmt in (Format.MACHO, Format.FAT):
        return _parse_macho(data)
    if fmt is Format.SCRIPT:
        return BinaryInfo(fmt=Format.SCRIPT, metadata={"interpreter": _shebang(data)})
    if fmt is Format.ARCHIVE:
        return BinaryInfo(fmt=Format.ARCHIVE)
    raise BinaryParseError("unrecognised binary format")


def _shebang(data: bytes) -> str:
    first = data.split(b"\n", 1)[0].decode("utf-8", "replace")
    return first[2:].strip()


# --- PE ----------------------------------------------------------------------

_PE_MACHINES = {
    0x014C: ("x86", 32),
    0x8664: ("x86_64", 64),
    0xAA64: ("arm64", 64),
    0x01C4: ("armv7", 32),
    0x0200: ("ia64", 64),
}

# Sections that are normal for a compiler to emit. Anything else is annotated, not
# rejected -- packers love unusual names and reviewers should see them.
_COMMON_PE_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".pdata", ".xdata",
    ".tls", ".edata", ".idata", ".didat", ".sdata", ".srdata", ".CRT", ".debug",
    ".gfids", ".00cfg", ".detourc", ".detourd",
}


def _parse_pe(data: bytes) -> BinaryInfo:
    info = BinaryInfo(fmt=Format.PE)
    if len(data) < 0x40:
        raise BinaryParseError("file too small to hold a DOS header")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        info.warnings.append("PE header offset points past end of file")
        return info

    machine, nsections = struct.unpack_from("<HH", data, e_lfanew + 4)
    (timestamp,) = struct.unpack_from("<I", data, e_lfanew + 8)
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]

    arch, bits = _PE_MACHINES.get(machine, (f"unknown-0x{machine:04x}", 0))
    info.arch, info.bits = arch, bits
    info.endian = "little"
    info.metadata["machine"] = f"0x{machine:04x}"
    info.metadata["timestamp"] = timestamp
    info.metadata["pe_signature"] = True

    opt_off = e_lfanew + 24
    magic = 0
    if opt_size and opt_off + 2 <= len(data):
        magic = struct.unpack_from("<H", data, opt_off)[0]
        info.metadata["pe_magic"] = f"0x{magic:04x}"
        if magic == 0x10B:
            info.bits = info.bits or 32
            if opt_off + 20 <= len(data):
                (info.entry_point,) = struct.unpack_from("<I", data, opt_off + 16)
        elif magic == 0x20B:
            info.bits = info.bits or 64
            if opt_off + 20 <= len(data):
                (info.entry_point,) = struct.unpack_from("<I", data, opt_off + 16)
        else:
            info.warnings.append(f"unexpected optional-header magic 0x{magic:04x}")

    section_table = opt_off + opt_size
    for i in range(nsections):
        off = section_table + i * 40
        if off + 40 > len(data):
            info.warnings.append(f"section table truncated at index {i}")
            break
        raw_name = data[off:off + 8].rstrip(b"\0")
        name = raw_name.decode("latin-1", "replace")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]

        body = data[raw_ptr:raw_ptr + raw_size] if raw_ptr < len(data) else b""
        if raw_size and len(body) < raw_size:
            info.warnings.append(f"section {name!r} extends past end of file")

        info.sections.append(Section(
            name=name,
            virtual_address=vaddr,
            virtual_size=vsize,
            raw_size=raw_size,
            entropy=shannon_entropy(body),
            executable=bool(chars & 0x20000000),
            writable=bool(chars & 0x80000000),
        ))

    if info.sections:
        odd = [s.name for s in info.sections if s.name not in _COMMON_PE_SECTIONS]
        if odd:
            info.metadata["unusual_sections"] = odd

    info.metadata["kernel_mode"] = bool(magic == 0x20B and
                                        info.metadata.get("machine") == "0x8664")
    return info


# --- ELF ---------------------------------------------------------------------

_ELF_TYPES = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}
_ELF_MACHINES = {
    0x03: "x86", 0x3E: "x86_64", 0x28: "arm", 0xB7: "aarch64",
    0xF3: "riscv", 0x15: "ppc", 0x16: "ppc64", 0x08: "mips",
}


def _parse_elf(data: bytes) -> BinaryInfo:
    info = BinaryInfo(fmt=Format.ELF)
    if len(data) < 0x34:
        raise BinaryParseError("file too small to hold an ELF header")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise BinaryParseError(f"invalid ELF class {ei_class}")
    if ei_data not in (1, 2):
        raise BinaryParseError(f"invalid ELF data encoding {ei_data}")

    endian = "little" if ei_data == 1 else "big"
    fmt = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2

    info.bits = 64 if is64 else 32
    info.endian = endian

    e_type, e_machine = struct.unpack_from(f"{fmt}HH", data, 16)
    info.metadata["elf_type"] = _ELF_TYPES.get(e_type, f"0x{e_type:x}")
    info.arch = _ELF_MACHINES.get(e_machine, f"unknown-0x{e_machine:04x}")

    if is64:
        if len(data) < 64:
            raise BinaryParseError("64-bit ELF header truncated")
        (info.entry_point,) = struct.unpack_from(f"{fmt}Q", data, 24)
        shoff, = struct.unpack_from(f"{fmt}Q", data, 40)
        shentsize, shnum, shstrndx = struct.unpack_from(f"{fmt}HHH", data, 58)
    else:
        (info.entry_point,) = struct.unpack_from(f"{fmt}I", data, 24)
        shoff, = struct.unpack_from(f"{fmt}I", data, 32)
        shentsize, shnum, shstrndx = struct.unpack_from(f"{fmt}HHH", data, 46)

    info.metadata["el_type"] = info.metadata["elf_type"]
    info.metadata["shstrndx"] = shstrndx

    if not shoff or not shnum:
        info.warnings.append("no section header table")
        return info

    # Cap the section count: a hostile file can claim 65535 sections and make the
    # loop pointless, and 4096 is well beyond any real binary.
    if shnum > 4096:
        info.warnings.append(f"implausible section count {shnum}, truncated to 4096")
        shnum = 4096

    headers: list[tuple[int, int, int, int, int, int]] = []
    for i in range(shnum):
        off = shoff + i * shentsize
        if off + shentsize > len(data):
            info.warnings.append(f"section header table truncated at index {i}")
            break
        if is64:
            name_off, sh_type, flags, addr, offset, size = struct.unpack_from(
                f"{fmt}IIQQQQ", data, off)
        else:
            name_off, sh_type, flags, addr, offset, size = struct.unpack_from(
                f"{fmt}IIIIII", data, off)
        headers.append((name_off, sh_type, flags, addr, offset, size))

    # Resolve names through the section-name string table.
    names_blob = b""
    if 0 <= shstrndx < len(headers):
        _, _, _, _, str_off, str_size = headers[shstrndx]
        names_blob = data[str_off:str_off + str_size]

    for name_off, sh_type, flags, addr, offset, size in headers:
        name = _elf_str(names_blob, name_off)
        # SHT_NOBITS (.bss) occupies no file space by definition -- its size is the
        # runtime allocation, so "extends past end of file" is meaningless for it.
        nobits = sh_type == 8
        body = data[offset:offset + size] if (offset < len(data) and not nobits) else b""
        if not nobits and size and len(body) < size:
            info.warnings.append(f"section {name!r} extends past end of file")
        info.sections.append(Section(
            name=name or f"<{sh_type}>",
            virtual_address=addr,
            virtual_size=size,
            raw_size=0 if nobits else size,
            entropy=shannon_entropy(body),
            executable=bool(flags & 0x4),  # SHF_EXECINSTR
            writable=bool(flags & 0x1),    # SHF_WRITE
        ))

    # Which symbols this object *imports* -- it defines the ones it exports, and a
    # library that implements ptrace is not a program that calls it.
    info.metadata["imports"] = _elf_imports(data, headers, is64, fmt)
    return info


def _elf_imports(data: bytes, headers, is64: bool, fmt: str) -> list[str]:
    """Undefined symbols from .dynsym, resolved through a linked string table."""
    symtab = next((h for h in headers if h[1] == 11), None)  # SHT_DYNSYM
    if symtab is None:
        return []
    _, _, _, _, sym_off, sym_size = symtab

    entsize = 24 if is64 else 16
    if not sym_size or sym_size % entsize:
        return []

    # Resolve names through the first non-null SHT_STRTAB section.
    strtab = None
    for i, h in enumerate(headers):
        if h[1] == 3 and i != 0 and h[4] and h[5] and h[4] < len(data):
            strtab = data[h[4]:h[4] + h[5]]
            break
    if strtab is None:
        return []

    out: list[str] = []
    for i in range(sym_size // entsize):
        off = sym_off + i * entsize
        if off + entsize > len(data):
            break
        if is64:
            st_name, _, _, st_shndx = struct.unpack_from(f"{fmt}IBBH", data, off)
        else:
            st_name, _, _, _, _, st_shndx = struct.unpack_from(
                f"{fmt}IIIBBH", data, off)
        if st_shndx == 0 and st_name:  # SHN_UNDEF == imported
            name = _elf_str(strtab, st_name)
            if name:
                out.append(name)
    return out


def _elf_str(blob: bytes, offset: int) -> str:
    if not blob or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    if end == -1:
        end = len(blob)
    return blob[offset:end].decode("utf-8", "replace")


# --- Mach-O ------------------------------------------------------------------

_CPU_TYPES = {
    7: ("x86", 32),
    0x01000007: ("x86_64", 64),
    12: ("arm", 32),
    0x0100000C: ("arm64", 64),
    0x0200000C: ("arm64_32", 32),
}


def _parse_macho(data: bytes) -> BinaryInfo:
    if len(data) < 8:
        raise BinaryParseError("file too small for a Mach-O header")

    be = struct.unpack_from(">I", data, 0)[0]
    if be in (0xCAFEBABE, 0xCAFEBABF):
        return _parse_fat(data, is64=(be == 0xCAFEBABF))

    info = BinaryInfo(fmt=Format.MACHO)
    # Read the magic big-endian: that ordering is what makes 0xFEEDFACF the
    # little-endian 64-bit constant once the bytes are reversed on disk.
    magic = struct.unpack_from(">I", data, 0)[0]
    bits, endian = _MACHO_MAGICS.get(magic, (0, ""))
    if not bits:
        raise BinaryParseError("not a Mach-O file")

    info.bits = bits
    info.endian = endian
    fmt = "<" if endian == "little" else ">"

    cputype, _, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
        f"{fmt}IIIIII", data, 4)
    info.arch = _CPU_TYPES.get(cputype, (f"cpu-0x{cputype:x}", bits))[0]
    info.metadata["filetype"] = filetype
    info.metadata["ncmds"] = ncmds
    info.metadata["flags"] = flags

    offset = 32 if bits == 64 else 28
    if ncmds > 4096:
        info.warnings.append(f"implausible load-command count {ncmds}")
        return info

    for i in range(ncmds):
        if offset + 8 > len(data):
            info.warnings.append(f"load commands truncated at index {i}")
            break
        cmd, cmdsize = struct.unpack_from(f"{fmt}II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            info.warnings.append(f"load command {i} has an invalid size {cmdsize}")
            break
        # LC_SEGMENT (0x1) / LC_SEGMENT_64 (0x19)
        if cmd in (0x1, 0x19):
            info.sections.extend(_macho_segment(data, offset, cmd, fmt, bits))
        offset += cmdsize

    return info


def _macho_segment(data: bytes, off: int, cmd: int, fmt: str, bits: int) -> list[Section]:
    """Sections inside an LC_SEGMENT command."""
    out: list[Section] = []
    try:
        if cmd == 0x19:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode("latin-1", "replace")
            nsects = struct.unpack_from(f"{fmt}I", data, off + 64)[0]
            sec_off = off + 72
            sec_size = 80
        else:
            segname = data[off + 8:off + 24].rstrip(b"\0").decode("latin-1", "replace")
            nsects = struct.unpack_from(f"{fmt}I", data, off + 48)[0]
            sec_off = off + 56
            sec_size = 68

        if nsects > 512:
            return out

        for i in range(nsects):
            s = sec_off + i * sec_size
            if s + sec_size > len(data):
                break
            sectname = data[s:s + 16].rstrip(b"\0").decode("latin-1", "replace")
            if cmd == 0x19:
                addr, size = struct.unpack_from(f"{fmt}QQ", data, s + 32)
                file_off = struct.unpack_from(f"{fmt}I", data, s + 48)[0]
                flags = struct.unpack_from(f"{fmt}I", data, s + 64)[0]
            else:
                addr, size = struct.unpack_from(f"{fmt}II", data, s + 32)
                file_off = struct.unpack_from(f"{fmt}I", data, s + 40)[0]
                flags = struct.unpack_from(f"{fmt}I", data, s + 56)[0]

            body = data[file_off:file_off + size] if file_off < len(data) else b""
            attrs = (flags >> 24) & 0xFF
            out.append(Section(
                name=f"{segname},{sectname}" if segname else sectname,
                virtual_address=addr,
                virtual_size=size,
                raw_size=size,
                entropy=shannon_entropy(body),
                executable=bool(attrs & 0x4) or "text" in sectname,
                writable="data" in sectname,
            ))
    except struct.error:
        pass
    return out


def _parse_fat(data: bytes, is64: bool) -> BinaryInfo:
    info = BinaryInfo(fmt=Format.FAT)
    nfat = struct.unpack_from(">I", data, 4)[0]
    if nfat > 20:
        raise BinaryParseError(f"implausible architecture count {nfat}")

    arches = []
    entry = 32 if is64 else 20
    for i in range(nfat):
        off = 8 + i * entry
        if off + 8 > len(data):
            info.warnings.append("fat architecture table truncated")
            break
        cputype = struct.unpack_from(">I", data, off)[0]
        arches.append(_CPU_TYPES.get(cputype, (f"cpu-0x{cputype:x}", 0))[0])

    info.metadata["architectures"] = arches
    info.arch = ",".join(arches)
    if len(arches) > 1:
        info.metadata["universal"] = True
    return info
