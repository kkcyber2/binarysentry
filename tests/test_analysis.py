"""Indicator rules and the CLI."""

import json

import pytest

from binarysentry.analysis import Severity, analyze
from binarysentry.cli import main
from binarysentry.fixtures import make_elf, make_macho, make_pe, make_script


def codes(analysis):
    return {i.code for i in analysis.indicators}


class TestExtensionMismatch:
    def test_pe_named_pdf_is_high_severity(self):
        analysis = analyze(make_pe(), filename="invoice.pdf")
        assert "extension-mismatch" in codes(analysis)
        assert analysis.verdict is Severity.HIGH

    def test_pe_named_exe_is_fine(self):
        analysis = analyze(make_pe(), filename="setup.exe")
        assert "extension-mismatch" not in codes(analysis)

    def test_elf_named_jpg_is_flagged(self):
        analysis = analyze(make_elf(), filename="photo.jpg")
        assert "extension-mismatch" in codes(analysis)

    def test_extension_check_is_case_insensitive(self):
        analysis = analyze(make_pe(), filename="INVOICE.PDF")
        assert "extension-mismatch" in codes(analysis)

    def test_no_filename_means_no_extension_claim(self):
        analysis = analyze(make_pe(), filename="")
        assert "extension-mismatch" not in codes(analysis)

    def test_document_format_never_triggers_it(self):
        analysis = analyze(make_script(), filename="notes.txt")
        assert "extension-mismatch" not in codes(analysis)


class TestPacking:
    def test_high_entropy_code_section_is_flagged(self):
        analysis = analyze(make_pe(sections=[
            (".text", 0x1000, 0x1000, True, False, bytes(range(256)) * 16),
        ]))
        assert "packed" in codes(analysis)
        assert analysis.verdict is Severity.MEDIUM

    def test_normal_code_is_not_flagged(self):
        analysis = analyze(make_pe(sections=[
            (".text", 0x1000, 0x1000, True, False, bytes(range(32)) * 32),
        ]))
        assert "packed" not in codes(analysis)

    def test_small_high_entropy_section_is_ignored(self):
        """Under 512 bytes the entropy estimate is too noisy to trust."""
        analysis = analyze(make_pe(sections=[
            (".text", 0x1000, 0x1000, True, False, bytes(range(256))),
        ]))
        assert "packed" not in codes(analysis)


class TestSections:
    def test_wx_section_is_high_severity(self):
        analysis = analyze(make_pe(sections=[
            (".text", 0x1000, 0x1000, True, True, b"\x90" * 0x200),
        ]))
        assert "wx-section" in codes(analysis)
        assert analysis.verdict is Severity.HIGH

    def test_normal_sections_do_not_warn(self):
        analysis = analyze(make_pe(sections=[
            (".text", 0x1000, 0x1000, True, False, b"\x90" * 0x200),
            (".data", 0x1000, 0x2000, False, True, b"\x01" * 0x200),
        ]))
        assert "wx-section" not in codes(analysis)


class TestImports:
    def test_injection_apis_are_detected(self):
        analysis = analyze(make_elf(imports=["VirtualAllocEx", "WriteProcessMemory"]))
        assert "suspicious-imports" in codes(analysis)
        indicator = next(i for i in analysis.indicators if i.code == "suspicious-imports")
        assert "VirtualAllocEx" in indicator.detail
        assert indicator.severity is Severity.HIGH

    def test_one_import_is_medium_not_high(self):
        analysis = analyze(make_elf(imports=["ptrace"]))
        indicator = next(i for i in analysis.indicators if i.code == "suspicious-imports")
        assert indicator.severity is Severity.MEDIUM

    def test_clean_binary_has_no_import_findings(self):
        analysis = analyze(make_elf(imports=["malloc", "printf"]))
        assert "suspicious-imports" not in codes(analysis)

    def test_defined_symbols_are_not_imports(self):
        """A library that exports ptrace must not be flagged for using it."""
        analysis = analyze(make_elf(imports=[]))
        assert "suspicious-imports" not in codes(analysis)

    def test_explanation_is_attached(self):
        """A scary name without a reason is not analysis."""
        analysis = analyze(make_elf(imports=["memfd_create"]))
        indicator = next(i for i in analysis.indicators if i.code == "suspicious-imports")
        assert "fileless" in indicator.detail


class TestSignature:
    def test_unsigned_pe_is_noted(self):
        analysis = analyze(make_pe())
        assert "unsigned" in codes(analysis)
        assert analysis.info.metadata["signed"] is False

    def test_certificate_presence_clears_the_indicator(self):
        analysis = analyze(make_pe(certificate_size=256))
        assert analysis.info.metadata["signed"] is True
        assert "unsigned" not in codes(analysis)

    def test_unsigned_macho_is_noted(self):
        analysis = analyze(make_macho())
        assert "unsigned" in codes(analysis)


class TestScripts:
    def test_shell_script_is_informational(self):
        analysis = analyze(make_script("/bin/bash"))
        assert "shell-script" in codes(analysis)
        assert analysis.verdict is Severity.INFO


class TestRobustness:
    def test_garbage_input_is_low_not_a_crash(self):
        analysis = analyze(b"\x00" * 500)
        assert "unparseable" in codes(analysis)
        assert analysis.verdict is Severity.LOW

    def test_truncated_pe_yields_warnings_not_exceptions(self):
        analysis = analyze(make_pe()[:0x50])
        assert analysis.info.fmt.value == "pe"

    def test_empty_input_does_not_raise(self):
        analysis = analyze(b"")
        assert analysis.info.fmt.value == "unknown"

    def test_verdict_is_the_worst_indicator(self):
        analysis = analyze(make_elf(imports=["ptrace", "process_vm_writev"]),
                           filename="x.pdf")
        assert analysis.verdict is Severity.HIGH
        assert analysis.suspicious is True

    def test_to_dict_serialises(self):
        payload = json.loads(json.dumps(analyze(make_pe()).to_dict()))
        assert "indicators" in payload
        assert payload["binary"]["format"] == "pe"


class TestCli:
    def test_clean_file_exits_zero(self, tmp_path, capsys):
        p = tmp_path / "clean.exe"
        p.write_bytes(make_pe())
        assert main([str(p)]) == 0

    def test_missing_file_exits_two(self, tmp_path):
        assert main([str(tmp_path / "absent.bin")]) == 2

    def test_json_output_parses(self, tmp_path, capsys):
        p = tmp_path / "a.exe"
        p.write_bytes(make_pe())
        main([str(p), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["binary"]["format"] == "pe"

    def test_quiet_prints_one_line(self, tmp_path, capsys):
        p = tmp_path / "a.exe"
        p.write_bytes(make_pe())
        main([str(p), "--quiet"])
        out = capsys.readouterr().out.strip()
        assert out.count("\n") == 0

    def test_fail_on_high_triggers_on_mismatch(self, tmp_path, capsys):
        p = tmp_path / "invoice.pdf"
        p.write_bytes(make_pe())
        assert main([str(p), "--fail-on", "high"]) == 1

    def test_fail_on_high_does_not_trigger_on_low(self, tmp_path):
        p = tmp_path / "a.elf"
        p.write_bytes(make_elf())
        # An unsigned ELF produces no high finding.
        assert main([str(p), "--fail-on", "high"]) == 0

    def test_sections_flag_lists_sections(self, tmp_path, capsys):
        p = tmp_path / "a.exe"
        p.write_bytes(make_pe())
        main([str(p), "--sections"])
        out = capsys.readouterr().out
        assert ".text" in out

    def test_human_output_states_the_verdict(self, tmp_path, capsys):
        p = tmp_path / "a.exe"
        p.write_bytes(make_pe())
        main([str(p)])
        assert "verdict:" in capsys.readouterr().out
