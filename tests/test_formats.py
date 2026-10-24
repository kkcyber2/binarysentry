"""Format detection and header parsing against spec-built fixtures."""

import struct

import pytest

from binarysentry.fixtures import make_elf, make_fat, make_macho, make_pe, make_script, make_zip
from binarysentry.formats import (
    BinaryParseError,
    Format,
    detect,
    parse,
    shannon_entropy,
)


class TestEntropy:
    def test_uniform_bytes_have_zero_entropy(self):
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_all_256_values_once_is_eight_bits(self):
        assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0, abs=0.01)

    def test_empty_is_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_text_is_low_entropy(self):
        assert shannon_entropy(b"the quick brown fox " * 100) < 4.5


class TestDetect:
    def test_pe_is_detected(self):
        assert detect(make_pe()) is Format.PE

    def test_elf_is_detected(self):
        assert detect(make_elf()) is Format.ELF

    def test_macho_is_detected(self):
        assert detect(make_macho()) is Format.MACHO

    def test_fat_is_detected(self):
        assert detect(make_fat()) is Format.FAT

    def test_shell_script_is_detected(self):
        assert detect(make_script()) is Format.SCRIPT

    def test_zip_is_archive(self):
        assert detect(make_zip()) is Format.ARCHIVE

    def test_empty_file_is_unknown(self):
        assert detect(b"") is Format.UNKNOWN

    def test_mz_without_pe_signature_is_unknown(self):
        """A bare DOS stub must not be reported as a PE."""
        assert detect(b"MZ" + b"\0" * 200) is Format.UNKNOWN

    def test_mz_pointing_past_eof_is_unknown(self):
        blob = bytearray(b"MZ" + b"\0" * 200)
        struct.pack_into("<I", blob, 0x3C, 0xFFFF)
        assert detect(bytes(blob)) is Format.UNKNOWN

    def test_truncated_input_does_not_raise(self):
        assert detect(b"\x7fE") is Format.UNKNOWN


class TestPE:
    def test_arch_and_bits_from_machine(self):
        info = parse(make_pe(machine=0x8664, magic=0x20B))
        assert info.fmt is Format.PE
        assert info.arch == "x86_64"
        assert info.bits == 64

    def test_x86_32(self):
        info = parse(make_pe(machine=0x014C, magic=0x10B))
        assert info.arch == "x86"
        assert info.bits == 32

    def test_entry_point_read_from_optional_header(self):
        info = parse(make_pe())
        assert info.entry_point == 0x1000

    def test_sections_are_parsed_with_flags(self):
        info = parse(make_pe(sections=[
            (".text", 0x1000, 0x1000, True, False, b"\x90" * 0x200),
            (".data", 0x1000, 0x2000, False, True, b"\x01" * 0x200),
        ]))
        names = [s.name for s in info.sections]
        assert names == [".text", ".data"]
        assert info.sections[0].executable is True
        assert info.sections[0].writable is False
        assert info.sections[1].executable is False
        assert info.sections[1].writable is True

    def test_high_entropy_executable_section_is_flagged_as_packed(self):
        info = parse(make_pe(sections=[
            (".text", 0x1000, 0x1000, True, False, bytes(range(256)) * 8),
        ]))
        assert info.high_entropy_sections, "uniform bytes should read as high entropy"

    def test_compressible_code_is_not_flagged(self):
        info = parse(make_pe(sections=[
            (".text", 0x1000, 0x1000, True, False, bytes(range(32)) * 32),
        ]))
        # 32 distinct values repeated is ~5 bits/byte, well under the threshold.
        assert info.high_entropy_sections == []

    def test_unusual_section_name_is_recorded(self):
        info = parse(make_pe(sections=[
            (".text", 0x1000, 0x1000, True, False, b"\x90" * 0x200),
            ("UPX0", 0x1000, 0x2000, True, False, b"\x90" * 0x200),
        ]))
        assert "UPX0" in info.metadata["unusual_sections"]

    def test_truncated_section_table_warns_instead_of_raising(self):
        blob = make_pe()
        truncated = blob[:0x40 + 24 + 240 + 8]
        info = parse(truncated)
        assert info.warnings


class TestELF:
    def test_64_bit_little_endian(self):
        info = parse(make_elf())
        assert info.fmt is Format.ELF
        assert info.bits == 64
        assert info.endian == "little"
        assert info.arch == "x86_64"

    def test_32_bit(self):
        info = parse(make_elf(is64=False, machine=0x03))
        assert info.bits == 32
        assert info.arch == "x86"

    def test_big_endian(self):
        info = parse(make_elf(endian="big"))
        assert info.endian == "big"

    def test_section_names_resolve_through_shstrtab(self):
        info = parse(make_elf(sections=[(".text", b"\x90" * 64, 0x4),
                                        (".rodata", b"\x01\x02" * 32, 0x2)]))
        names = [s.name for s in info.sections]
        assert ".text" in names
        assert ".rodata" in names

    def test_executable_flag_maps_to_the_x_bit(self):
        info = parse(make_elf(sections=[(".text", b"\x90" * 64, 0x4)]))
        text = next(s for s in info.sections if s.name == ".text")
        assert text.executable is True

    def test_write_flag(self):
        info = parse(make_elf(sections=[(".data", b"\x01" * 64, 0x1)]))
        data = next(s for s in info.sections if s.name == ".data")
        assert data.writable is True

    def test_rejects_bad_class(self):
        blob = bytearray(make_elf())
        blob[4] = 9
        with pytest.raises(BinaryParseError):
            parse(bytes(blob))

    def test_rejects_bad_data_encoding(self):
        blob = bytearray(make_elf())
        blob[5] = 9
        with pytest.raises(BinaryParseError):
            parse(bytes(blob))

    def test_aarch64(self):
        info = parse(make_elf(machine=0xB7))
        assert info.arch == "aarch64"

    def test_truncated_header_raises(self):
        with pytest.raises(BinaryParseError):
            parse(make_elf()[:20])

    def test_no_section_table_warns(self):
        blob = bytearray(make_elf())
        # Zero the shoff field (offset 40 in a 64-bit header).
        struct.pack_into("<Q", blob, 40, 0)
        info = parse(bytes(blob))
        assert "no section header table" in " ".join(info.warnings)


class TestMachO:
    def test_64_bit_arm(self):
        info = parse(make_macho())
        assert info.fmt is Format.MACHO
        assert info.bits == 64
        assert info.arch == "arm64"

    def test_x86_64(self):
        info = parse(make_macho(cputype=0x01000007))
        assert info.arch == "x86_64"

    def test_sections_from_segment_command(self):
        info = parse(make_macho(sections=[("__text", b"\x90" * 64),
                                          ("__data", b"\x01" * 64)]))
        names = [s.name for s in info.sections]
        assert any("__text" in n for n in names)

    def test_fat_lists_every_architecture(self):
        info = parse(make_fat(arches=3))
        assert info.fmt is Format.FAT
        assert len(info.metadata["architectures"]) == 3
        assert info.metadata["universal"] is True

    def test_single_arch_fat_is_not_universal(self):
        info = parse(make_fat(arches=1))
        assert "universal" not in info.metadata

    def test_implausible_arch_count_raises(self):
        blob = struct.pack(">II", 0xCAFEBABE, 99) + b"\0" * 200
        with pytest.raises(BinaryParseError):
            parse(blob)


class TestOther:
    def test_shebang_interpreter_is_captured(self):
        info = parse(make_script("/usr/bin/env python3"))
        assert info.fmt is Format.SCRIPT
        assert info.metadata["interpreter"] == "/usr/bin/env python3"

    def test_unknown_format_raises(self):
        with pytest.raises(BinaryParseError):
            parse(b"just some text, no signature")

    def test_to_dict_is_json_shaped(self):
        import json

        payload = json.loads(json.dumps(parse(make_pe()).to_dict()))
        assert payload["format"] == "pe"
        assert payload["entry_point"].startswith("0x")
