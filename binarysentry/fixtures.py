"""Build minimal but structurally valid binaries for tests.

The fixtures are assembled byte by byte from the format specs rather than checked in
as opaque blobs. That way a test failure points at a real disagreement with the spec,
and the reader can see exactly what a valid header looks like.
"""

from __future__ import annotations

import struct

__all__ = ["make_pe", "make_elf", "make_macho", "make_fat", "make_script", "make_zip"]


def _pad(data: bytes, size: int) -> bytes:
    return data + b"\0" * max(0, size - len(data))


def _compressible(size: int) -> bytes:
    """Low-entropy filler that stands in for real code."""
    pattern = bytes(range(32)) * 8
    return (pattern * ((size // len(pattern)) + 1))[:size]


def _randomish(size: int, seed: int = 7) -> bytes:
    """Deterministic high-entropy bytes (no crypto dependency needed)."""
    out = bytearray()
    x = seed
    while len(out) < size:
        x = (1103515245 * x + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def make_pe(
    *,
    sections: list[tuple[str, int, int, bool, bool, bytes]] | None = None,
    machine: int = 0x8664,
    magic: int = 0x20B,
    certificate_size: int = 0,
    extra: bytes = b"",
) -> bytes:
    """A PE image.

    ``sections`` entries are ``(name, vsize, vaddr, executable, writable, body)``.
    """
    if sections is None:
        sections = [(".text", 0x1000, 0x1000, True, False, _compressible(0x200))]

    e_lfanew = 0x40
    opt_size = 240 if magic == 0x20B else 224
    headers_size = e_lfanew + 24 + opt_size + 40 * len(sections)

    section_table = b""
    body_blob = b""
    raw_cursor = _align(headers_size, 0x200)

    for name, vsize, vaddr, exe, writable, body in sections:
        raw_ptr = raw_cursor
        raw_size = _align(len(body), 0x200)
        chars = 0x40000000  # IMAGE_SCN_MEM_READ
        if exe:
            chars |= 0x20000000  # IMAGE_SCN_MEM_EXECUTE
        if writable:
            chars |= 0x80000000  # IMAGE_SCN_MEM_WRITE
        section_table += struct.pack(
            "<8sIIIIIIHHI",
            name.encode()[:8].ljust(8, b"\0"),
            vsize, vaddr, raw_size, raw_ptr, 0, 0, 0, 0, chars,
        )
        body_blob += _pad(body, raw_size)
        raw_cursor += raw_size

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    file_header = struct.pack(
        "<HHIIIHH",
        machine,
        len(sections),
        0x5F5E1000,          # timestamp
        0, 0,                # symbol table, count
        opt_size,
        0x22,                # executable | large address aware
    )

    optional = bytearray(opt_size)
    struct.pack_into("<H", optional, 0, magic)
    struct.pack_into("<I", optional, 16, 0x1000)   # entry point
    if certificate_size:
        dirs = 112 if magic == 0x20B else 96
        struct.pack_into("<I", optional, dirs + 32, 0x200)          # cert offset
        struct.pack_into("<I", optional, dirs + 36, certificate_size)

    image = bytes(dos) + b"PE\0\0" + file_header + bytes(optional) + section_table
    image = _pad(image, _align(headers_size, 0x200))
    image += body_blob
    if certificate_size:
        image += b"\x30\x82" + _randomish(max(0, certificate_size - 2), seed=3)
    return image + extra


def _align(n: int, to: int) -> int:
    return (n + to - 1) // to * to


def make_elf(
    *,
    is64: bool = True,
    endian: str = "little",
    machine: int = 0x3E,
    sections: list[tuple[str, bytes, int]] | None = None,
    entry: int = 0x1000,
    imports: list[str] | None = None,
) -> bytes:
    """An ELF with a real section-header table, name table and .dynsym.

    ``sections`` entries are ``(name, body, flags)``. ``imports`` become undefined
    symbols in a genuine .dynsym, which is how the analyser decides what a binary
    calls rather than what it merely contains.
    """
    if sections is None:
        sections = [(".text", _compressible(0x200), 0x4), (".data", b"\x01\x02" * 64, 0x1)]
    imports = list(imports or [])

    fmt = "<" if endian == "little" else ">"
    ehsize = 64 if is64 else 52
    shentsize = 64 if is64 else 40

    # Section 0 is the reserved null section; the last one holds the names.
    n_sections = len(sections) + 2 + (2 if imports else 0)
    shstrtab_names = b"\0" + b"".join(
        name.encode() + b"\0" for name, _, _ in sections
    ) + b".shstrtab\0"

    # Lay out bodies after the ELF header.
    cursor = ehsize
    laid_out: list[tuple[int, int, bytes, int]] = []  # name_off, offset, body, flags
    name_off = 1
    for name, body, flags in sections:
        cursor = _align(cursor, 16)
        laid_out.append((name_off, cursor, body, flags))
        name_off += len(name) + 1
        cursor += len(body)

    dynstr = b""
    dynsym = b""
    if imports:
        dynstr = b"\0" + b"".join(s.encode() + b"\0" for s in imports)
        entsize = 24 if is64 else 16
        dynsym = b"\0" * entsize  # symbol 0 is always the null symbol
        off = 1
        for sym in imports:
            if is64:
                dynsym += struct.pack(f"{fmt}IBBHQQ", off, 0x12, 0, 0, 0, 0)
            else:
                dynsym += struct.pack(f"{fmt}IIIBBH", off, 0, 0, 0x12, 0, 0)
            off += len(sym) + 1

    dynstr_off = dynsym_off = 0
    if imports:
        dynstr_off = _align(cursor, 16)
        cursor = dynstr_off + len(dynstr)
        dynsym_off = _align(cursor, 16)
        cursor = dynsym_off + len(dynsym)

    shstrtab_off = _align(cursor, 16)
    cursor = shstrtab_off + len(shstrtab_names)
    shoff = _align(cursor, 16)

    blob = bytearray(_pad(b"", shoff))

    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2 if is64 else 1
    ident[5] = 1 if endian == "little" else 2
    ident[6] = 1  # version
    blob[0:16] = ident

    e_type = 2  # ET_EXEC
    if is64:
        struct.pack_into(f"{fmt}HHIQQQIHHHHHH", blob, 16,
                         e_type, machine, 1, entry, 0, shoff, 0,
                         ehsize, 56, 0, 64, n_sections, n_sections - 1)
    else:
        struct.pack_into(f"{fmt}HHIIIIIHHHHHH", blob, 16,
                         e_type, machine, 1, entry, 0, shoff, 0,
                         ehsize, 32, 0, 40, n_sections, n_sections - 1)
    for (name_off_v, offset, body, flags) in laid_out:
        blob[offset:offset + len(body)] = body
    if imports:
        blob[dynstr_off:dynstr_off + len(dynstr)] = dynstr
        blob[dynsym_off:dynsym_off + len(dynsym)] = dynsym
    blob[shstrtab_off:shstrtab_off + len(shstrtab_names)] = shstrtab_names

    def shdr(name_i: int, sh_type: int, flags: int, addr: int, off: int, size: int,
             link: int = 0) -> bytes:
        if is64:
            return struct.pack(f"{fmt}IIQQQQIIQQ", name_i, sh_type, flags, addr,
                               off, size, link, 0, 1, 0)
        return struct.pack(f"{fmt}IIIIIIIIII", name_i, sh_type, flags, addr,
                           off, size, link, 0, 1, 0)

    headers = shdr(0, 0, 0, 0, 0, 0)
    for (name_off_v, offset, body, flags) in laid_out:
        headers += shdr(name_off_v, 1, flags, 0x1000, offset, len(body))
    if imports:
        # .dynstr precedes .dynsym, so the symbol table links to the next index.
        dynstr_idx = n_sections - 3
        headers += shdr(0, 3, 0, 0, dynstr_off, len(dynstr))
        headers += shdr(0, 11, 0, 0, dynsym_off, len(dynsym), link=dynstr_idx)
    headers += shdr(len(shstrtab_names) - len(b".shstrtab\0"), 3, 0, 0,
                    shstrtab_off, len(shstrtab_names))

    blob[shoff:shoff + len(headers)] = headers
    return bytes(blob)


def make_macho(*, is64: bool = True, cputype: int = 0x0100000C,
               sections: list[tuple[str, bytes]] | None = None) -> bytes:
    """A thin Mach-O with one LC_SEGMENT_64 holding the given sections."""
    if sections is None:
        sections = [("__text", _compressible(0x100))]

    endian = "<"
    magic = 0xFEEDFACF if is64 else 0xFEEDFACE
    sizeofcmds = 72 + 80 * len(sections)
    header_size = 32 if is64 else 28
    data_off = header_size + sizeofcmds

    segname = b"__TEXT".ljust(16, b"\0")
    cmd = 0x19 if is64 else 0x1
    cmdsize = 72 + 80 * len(sections)

    blob = bytearray()
    if is64:
        blob += struct.pack(f"{endian}IIIIIIII", magic, cputype, 0, 2, 1, cmdsize, 0, 0)
    else:
        blob += struct.pack(f"{endian}IIIIIII", magic, cputype, 0, 2, 1, cmdsize, 0)

    total = len(b"".join(b for _, b in sections))
    seg = struct.pack(f"{endian}II16sQQQQiiII", cmd, cmdsize, segname,
                      data_off, total, data_off, total, 7, 5,
                      len(sections), 0)
    blob += seg

    cursor = data_off
    bodies = b""
    for name, body in sections:
        sect = struct.pack(
            f"{endian}16s16sQQIIIIIIII",
            name.encode().ljust(16, b"\0"),
            segname,
            0x1000, len(body), cursor, 4, 0, 0, 0, 0, 0, 0,
        )
        blob += sect
        bodies += _pad(body, 16)
        cursor += len(body)

    return bytes(blob) + bodies


def make_fat(arches: int = 2) -> bytes:
    """A universal binary header claiming ``arches`` slices."""
    blob = bytearray(struct.pack(">II", 0xCAFEBABE, arches))
    for i in range(arches):
        blob += struct.pack(">IIIII", 0x0100000C if i == 0 else 0x01000007, 0, 0, 0, 0)
    return bytes(blob)


def make_script(interpreter: str = "/bin/sh") -> bytes:
    return f"#!{interpreter}\necho hello\n".encode()


def make_zip() -> bytes:
    return b"PK\x03\x04" + b"\0" * 26
