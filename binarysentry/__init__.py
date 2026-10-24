"""Static triage for PE, ELF and Mach-O binaries."""

from .formats import (
    BinaryInfo,
    BinaryParseError,
    Format,
    Import,
    Section,
    detect,
    parse,
    shannon_entropy,
)
from .analysis import Analysis, Indicator, Severity, analyze

__all__ = [
    "BinaryInfo",
    "BinaryParseError",
    "Format",
    "Import",
    "Section",
    "detect",
    "parse",
    "shannon_entropy",
    "Analysis",
    "Indicator",
    "Severity",
    "analyze",
]

__version__ = "1.0.0"
