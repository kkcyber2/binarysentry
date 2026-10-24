"""Turning a parsed binary into findings.

A header dump is not a security result. What a reviewer needs is: is this packed,
what does it import, does it look like a loader, does it carry a certificate, and
does the file's *claimed* type match what it actually is. Each of those is a rule
here with a stated rationale.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .formats import BinaryInfo, BinaryParseError, Format, detect, parse

__all__ = ["Indicator", "Analysis", "analyze", "MISMATCH_EXTENSIONS"]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Extensions that promise a *document* rather than an executable. A PE or ELF behind
# one of these is the single most common delivery trick in commodity malware, and it
# is cheap to detect because the file itself tells you what it is.
MISMATCH_EXTENSIONS = frozenset({
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".zip", ".rar",
})

_EXECUTABLE_FORMATS = {Format.PE, Format.ELF, Format.MACHO, Format.FAT}

# Imports that a normal application does not usually need. Each entry says why,
# because a list of scary names without justification is not analysis.
_SUSPICIOUS_IMPORTS = {
    # Windows
    "VirtualAllocEx": "allocate memory in another process (injection)",
    "WriteProcessMemory": "write into another process (injection)",
    "CreateRemoteThread": "start a thread in another process (injection)",
    "SetWindowsHookEx": "intercept input system-wide (keylogging)",
    "GetAsyncKeyState": "read raw keystrokes (keylogging)",
    "AdjustTokenPrivileges": "escalate process privileges",
    "NtUnmapViewOfSection": "process hollowing",
    "MiniDumpWriteDump": "dump process memory (credential theft)",
    "CryptEncrypt": "encrypt data (ransomware behaviour)",
    "URLDownloadToFile": "pull a payload over HTTP",
    "WinExec": "launch a process without a shell",
    "LsaEnumerateLogonSessions": "enumerate logon credentials",
    # POSIX
    "ptrace": "attach to a running process (debugging or injection)",
    "process_vm_writev": "write into another process's memory (injection)",
    "memfd_create": "execute code from an anonymous file (fileless execution)",
    "prctl": "often used alongside memfd for privilege changes",
}


@dataclass
class Indicator:
    code: str
    severity: Severity
    message: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "detail": self.detail,
        }


@dataclass
class Analysis:
    info: BinaryInfo
    indicators: list[Indicator] = field(default_factory=list)

    @property
    def verdict(self) -> Severity:
        if not self.indicators:
            return Severity.INFO
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]
        return max((i.severity for i in self.indicators), key=order.index)

    @property
    def suspicious(self) -> bool:
        return any(i.severity in (Severity.MEDIUM, Severity.HIGH) for i in self.indicators)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "suspicious": self.suspicious,
            "binary": self.info.to_dict(),
            "indicators": [i.to_dict() for i in self.indicators],
        }


def analyze(data: bytes, filename: str = "") -> Analysis:
    """Parse ``data`` and run every indicator rule over the result."""
    try:
        info = parse(data)
    except BinaryParseError as exc:
        analysis = Analysis(info=BinaryInfo(fmt=Format.UNKNOWN, warnings=[str(exc)]))
        analysis.indicators.append(Indicator(
            "unparseable", Severity.LOW, f"could not parse the binary: {exc}"))
        return analysis

    analysis = Analysis(info=info)

    _check_extension(analysis, filename)
    _check_packing(analysis)
    _check_sections(analysis)
    _check_imports(analysis, data)
    _check_signature(analysis, data)
    _check_scripts(analysis)

    for warning in info.warnings:
        analysis.indicators.append(
            Indicator("parse-warning", Severity.LOW, warning)
        )

    return analysis


def _check_extension(analysis: Analysis, filename: str) -> None:
    info = analysis.info
    if info.fmt not in _EXECUTABLE_FORMATS or not filename:
        return
    lower = filename.lower()
    dot = lower.rfind(".")
    if dot == -1:
        return
    ext = lower[dot:]
    if ext in MISMATCH_EXTENSIONS:
        analysis.indicators.append(Indicator(
            "extension-mismatch", Severity.HIGH,
            f"file is named {ext} but contains a {info.fmt.value.upper()} executable",
            "The extension promises a document; the content is machine code.",
        ))


def _check_packing(analysis: Analysis) -> None:
    info = analysis.info
    packed = info.high_entropy_sections
    if packed:
        names = ", ".join(s.name for s in packed)
        analysis.indicators.append(Indicator(
            "packed", Severity.MEDIUM,
            f"{len(packed)} executable section(s) look compressed or encrypted: {names}",
            "High entropy in code means the real code is not visible to static review.",
        ))

    # A tiny binary with almost no sections is characteristic of a dropper.
    if info.fmt in _EXECUTABLE_FORMATS and len(info.sections) <= 2 and info.bits:
        analysis.indicators.append(Indicator(
            "minimal-structure", Severity.LOW,
            f"only {len(info.sections)} section(s) present",
            "Very few sections suggests a stub, dropper or heavily stripped binary.",
        ))


def _check_sections(analysis: Analysis) -> None:
    info = analysis.info
    for section in info.sections:
        if section.executable and section.writable:
            analysis.indicators.append(Indicator(
                "wx-section", Severity.HIGH,
                f"section {section.name!r} is both writable and executable",
                "W^X is violated, which is how self-modifying and injected code runs.",
            ))

    unusual = info.metadata.get("unusual_sections")
    if unusual:
        analysis.indicators.append(Indicator(
            "unusual-sections", Severity.LOW,
            f"non-standard section names: {', '.join(unusual)}",
            "Common with packers and protectors; also legal with custom toolchains.",
        ))


def _check_imports(analysis: Analysis, data: bytes) -> None:
    """Match suspicious API names against what the file actually imports.

    For ELF we walk .dynsym and keep only undefined (SHN_UNDEF) symbols: a library
    that *defines* ptrace is not a program that calls it, and flagging libc for
    exporting its own API is a false positive. PE and Mach-O have no equally cheap
    symbol-linkage walk here, so they fall back to a whole-file name scan -- the
    names still appear in the import table, and the alternative is missing a table
    we failed to parse.
    """
    imported = set(analysis.info.metadata.get("imports") or [])
    if imported:
        hits = [(api, reason) for api, reason in _SUSPICIOUS_IMPORTS.items()
                if api in imported]
    else:
        hits = [(api, reason) for api, reason in _SUSPICIOUS_IMPORTS.items()
                if api.encode() in data]

    if hits:
        detail = "; ".join(f"{api} -> {reason}" for api, reason in hits)
        severity = Severity.HIGH if len(hits) >= 2 else Severity.MEDIUM
        analysis.indicators.append(Indicator(
            "suspicious-imports", severity,
            f"{len(hits)} security-relevant API reference(s) present",
            detail,
        ))


def _check_signature(analysis: Analysis, data: bytes) -> None:
    info = analysis.info
    if info.fmt is Format.PE:
        # The certificate table is referenced from the optional header's data
        # directory entry 4; its presence is a cheap, reliable signal.
        has_cert = _pe_has_certificate(data)
        info.metadata["signed"] = has_cert
        if not has_cert:
            analysis.indicators.append(Indicator(
                "unsigned", Severity.LOW, "no Authenticode certificate present",
                "Unsigned binaries cannot be attributed to a publisher.",
            ))
    elif info.fmt is Format.MACHO:
        has_sig = b"\xfa\xde\x0c\xc0" in data or b"\xfa\xde\x0c\xc1" in data
        info.metadata["signed"] = has_sig
        if not has_sig:
            analysis.indicators.append(Indicator(
                "unsigned", Severity.LOW, "no code signature present",
            ))


def _pe_has_certificate(data: bytes) -> bool:
    import struct

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        opt = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        # Data directories start at 112 for PE32+ and 96 for PE32; entry 4 is at
        # +32 from the start of the directory array.
        dirs = opt + (112 if magic == 0x20B else 96)
        size = struct.unpack_from("<I", data, dirs + 32 + 4)[0]
        return size > 0
    except struct.error:
        return False


def _check_scripts(analysis: Analysis) -> None:
    info = analysis.info
    if info.fmt is not Format.SCRIPT:
        return
    interpreter = info.metadata.get("interpreter", "")
    info.metadata["interpreter"] = interpreter
    if any(shell in interpreter for shell in ("sh", "bash", "zsh", "dash")):
        analysis.indicators.append(Indicator(
            "shell-script", Severity.INFO,
            f"runs under {interpreter}",
            "Shell scripts execute with the privileges of whoever runs them.",
        ))
