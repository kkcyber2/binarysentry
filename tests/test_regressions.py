"""Regression tests for false positives found against real system binaries.

These exist because the analyser once reported HIGH risk for /bin/ls and libc:
.bss is SHT_NOBITS and occupies no file space, and libc *exports* ptrace rather
than importing it. Both were real bugs, so both are pinned here.
"""

import os

import pytest

from binarysentry.analysis import Severity, analyze
from binarysentry.fixtures import make_elf
from binarysentry.formats import parse

REAL_ELF = "/bin/ls"
REAL_LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"


class TestNobits:
    def test_bss_is_not_reported_as_truncated(self):
        info = parse(make_elf(sections=[
            (".text", b"\x90" * 64, 0x4),
            (".bss", b"", 0x3),
        ]))
        assert not [w for w in info.warnings if ".bss" in w]

    def test_bss_has_zero_raw_size(self):
        info = parse(make_elf(sections=[
            (".text", b"\x90" * 64, 0x4),
            (".bss", b"", 0x3),
        ]))
        bss = next(s for s in info.sections if s.name == ".bss")
        assert bss.raw_size == 0

    def test_bss_entropy_is_zero_not_misleading(self):
        info = parse(make_elf(sections=[(".bss", b"", 0x3)]))
        bss = next(s for s in info.sections if s.name == ".bss")
        assert bss.entropy == 0.0


class TestDefinedVersusImported:
    def test_defining_a_dangerous_api_is_not_importing_it(self):
        """libc implements ptrace; that must not make libc look malicious."""
        analysis = analyze(make_elf(imports=["malloc"]))
        assert "suspicious-imports" not in {i.code for i in analysis.indicators}

    def test_importing_it_is_flagged(self):
        analysis = analyze(make_elf(imports=["ptrace"]))
        assert "suspicious-imports" in {i.code for i in analysis.indicators}

    def test_imports_are_collected_from_dynsym(self):
        info = parse(make_elf(imports=["malloc", "free", "ptrace"]))
        assert set(info.metadata["imports"]) == {"malloc", "free", "ptrace"}

    def test_no_dynsym_means_empty_imports(self):
        info = parse(make_elf())
        assert info.metadata["imports"] == []


@pytest.mark.skipif(not os.path.exists(REAL_ELF), reason="no system ELF to test")
class TestAgainstRealBinaries:
    def test_ls_has_no_high_findings(self):
        with open(REAL_ELF, "rb") as fh:
            analysis = analyze(fh.read(), filename="ls")
        assert analysis.verdict is not Severity.HIGH

    def test_ls_sections_are_parsed(self):
        with open(REAL_ELF, "rb") as fh:
            info = parse(fh.read())
        assert len(info.sections) > 10
        assert any(s.name == ".text" for s in info.sections)

    @pytest.mark.skipif(not os.path.exists(REAL_LIBC), reason="no libc to test")
    def test_libc_is_not_flagged_high(self):
        """It exports every dangerous API it wraps; none of that is an import."""
        with open(REAL_LIBC, "rb") as fh:
            analysis = analyze(fh.read(), filename="libc.so.6")
        assert analysis.verdict is not Severity.HIGH
