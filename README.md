# binarysentry

Static triage for PE, ELF and Mach-O binaries.

A file named `invoice.pdf` that is really a Windows executable is the oldest trick
in commodity malware, and it is invisible to anything that trusts the extension.
`binarysentry` parses the actual container headers, measures per-section entropy,
reads the import table, and explains every risk it reports.

```console
$ binarysentry invoice.pdf
invoice.pdf  (147.8KB)
  format   PE
  arch     x86_64, 64-bit, little-endian
  entry    0x1000
  sections 2

  HIGH   file is named .pdf but contains a PE executable
         The extension promises a document; the content is machine code.
  MEDIUM 2 executable section(s) look compressed or encrypted: .text
         High entropy in code means the real code is not visible to static review.

verdict: HIGH
This binary has findings that warrant manual review before execution.
```

## Why not `file` and a YARA rule

`file` tells you the container. It does not tell you whether the code section is
packed, whether the section is writable *and* executable, whether the binary calls
`WriteProcessMemory`, or whether the file is lying about what it is. Each of those
is a separate, cheap signal, and together they make an actual triage decision
instead of a label.

The import check is deliberately narrow. An earlier version scanned the whole file
for dangerous API names and reported `/bin/ls` and `libc.so.6` as HIGH risk —
libc *exports* `ptrace`, which is the opposite of calling it. The current version
walks `.dynsym` and keeps only `SHN_UNDEF` symbols. There is a regression test for
this that runs against the real binaries on the machine.

## Install

```console
git clone https://github.com/kkcyber2/binarysentry
cd binarysentry
pip install -e ".[dev]"
```

## Use

```console
binarysentry suspicious.pdf          # human-readable triage
binarysentry suspicious.pdf --json   # machine-readable
binarysentry ./build/ --fail-on high # scan a directory, exit 1 on any HIGH
binarysentry app.exe --sections      # include the section table
```

Exit codes: `0` clean (or below the `--fail-on` threshold), `1` threshold exceeded,
`2` the file could not be read.

## What it checks

| Signal | Severity | Why |
|---|---|---|
| Extension claims a document, content is an executable | HIGH | The single most common delivery trick |
| A section is writable *and* executable | HIGH | W^X violation — self-modifying or injected code |
| Two or more suspicious imports | HIGH | A combination like `VirtualAllocEx` + `WriteProcessMemory` is injection |
| One suspicious import | MEDIUM | Worth a look on its own |
| High-entropy executable section (>512 bytes) | MEDIUM | Packed or encrypted: the real code is hidden |
| No signature / certificate | LOW | Cannot be attributed to a publisher |
| Non-standard section name | LOW | Common with packers; also legal with custom toolchains |
| Very few sections | LOW | Stub, dropper or heavily stripped binary |
| Unparseable input | LOW | Reported, never a crash |

## Scope and limits

This is static triage, not a sandbox. It will not tell you what a binary *does* —
only that it is worth a closer look. The entropy heuristic needs at least 512 bytes
in a section to be meaningful, so small packed stubs can slip past it. PE and Mach-O
imports come from a whole-file name scan rather than a full import-table walk;
ELF imports are genuinely parsed.

It never executes the file.

## Tests

```console
python -m pytest
```

85 tests. The fixtures are assembled byte by byte from the format specifications
rather than checked in as opaque blobs, so a failure points at a real disagreement
with the spec. Some tests run against the system's own `/bin/ls` and `libc.so.6`.

## Licence

MIT — see [LICENSE](LICENSE).

Konain Sultan Khan (KK) · [github.com/kkcyber2](https://github.com/kkcyber2) · LinkedIn: _to be added_
