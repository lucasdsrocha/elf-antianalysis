#!/usr/bin/env python3
"""corromper.py — Corrupts ONE field of the SHT/PHT/EHDR of an ELF64 binary
and writes a modified copy for manual analysis in GDB / IDA / Ghidra.
The original file is NEVER modified.

Self-contained: does not import strip.py or the test harness (structs are
defined locally).

Examples:
    python3 corromper.py ./target --list
    # full battery (zero, one, max, maxsigned, signbit) for a field:
    python3 corromper.py ./target --field sh_size --index 34 --run
    python3 corromper.py ./target --field e_shoff --run
    # or a single explicit value:
    python3 corromper.py ./target --field sh_entsize --index 34 --value 0

Without --value, generates all 5 patterns at once (one file per pattern).
Named values: zero | one | max | maxsigned | signbit
(or an integer: 1234 decimal, or 0x... hexadecimal)
"""
from __future__ import annotations

import argparse
import ctypes
import os
import struct
import subprocess
import sys


# ELF64 structures (based on the System V ABI specification)

class Elf64_Ehdr(ctypes.Structure):
    _fields_ = [
        ("e_ident", ctypes.c_ubyte * 16), ("e_type", ctypes.c_uint16),
        ("e_machine", ctypes.c_uint16),   ("e_version", ctypes.c_uint32),
        ("e_entry", ctypes.c_uint64),     ("e_phoff", ctypes.c_uint64),
        ("e_shoff", ctypes.c_uint64),     ("e_flags", ctypes.c_uint32),
        ("e_ehsize", ctypes.c_uint16),    ("e_phentsize", ctypes.c_uint16),
        ("e_phnum", ctypes.c_uint16),     ("e_shentsize", ctypes.c_uint16),
        ("e_shnum", ctypes.c_uint16),     ("e_shstrndx", ctypes.c_uint16),
    ]

class Elf64_Shdr(ctypes.Structure):
    _fields_ = [
        ("sh_name", ctypes.c_uint32),  ("sh_type", ctypes.c_uint32),
        ("sh_flags", ctypes.c_uint64), ("sh_addr", ctypes.c_uint64),
        ("sh_offset", ctypes.c_uint64),("sh_size", ctypes.c_uint64),
        ("sh_link", ctypes.c_uint32),  ("sh_info", ctypes.c_uint32),
        ("sh_addralign", ctypes.c_uint64), ("sh_entsize", ctypes.c_uint64),
    ]

class Elf64_Phdr(ctypes.Structure):
    _fields_ = [
        ("p_type", ctypes.c_uint32),  ("p_flags", ctypes.c_uint32),
        ("p_offset", ctypes.c_uint64),("p_vaddr", ctypes.c_uint64),
        ("p_paddr", ctypes.c_uint64), ("p_filesz", ctypes.c_uint64),
        ("p_memsz", ctypes.c_uint64), ("p_align", ctypes.c_uint64),
    ]

# Field prefix -> (table label, struct type, read by kernel at runtime)
PREFIX = {
    "e_":  ("EHDR", Elf64_Ehdr, False),
    "sh_": ("SHT",  Elf64_Shdr, False),  # kernel ignores the SHT: safe to corrupt
    "p_":  ("PHT",  Elf64_Phdr, True),   # kernel reads the PHT: may break execution
}

PT_NAMES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
            6: "PHDR", 7: "TLS", 0x6474e550: "GNU_EH_FRAME",
            0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO",
            0x6474e553: "GNU_PROPERTY"}
SHT_NAMES = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
             6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 11: "DYNSYM",
             14: "INIT_ARRAY", 15: "FINI_ARRAY", 0x6ffffff6: "GNU_HASH"}


# Helpers

def read_ehdr(raw: bytes) -> Elf64_Ehdr:
    if raw[:4] != b"\x7fELF":
        sys.exit("Not an ELF file (magic number missing).")
    if raw[4] != 2:
        sys.exit("Only ELF64 is supported (EI_CLASS != 2).")
    return Elf64_Ehdr.from_buffer_copy(raw[:ctypes.sizeof(Elf64_Ehdr)])


def section_names(raw: bytes, h: Elf64_Ehdr) -> list[str]:
    """Read section names from the .shstrtab string table."""
    if h.e_shnum == 0:
        return []
    shstr_hdr_off = h.e_shoff + h.e_shstrndx * h.e_shentsize
    shstr = Elf64_Shdr.from_buffer_copy(raw[shstr_hdr_off:shstr_hdr_off + 64])
    names = []
    for i in range(h.e_shnum):
        off = h.e_shoff + i * h.e_shentsize
        sh = Elf64_Shdr.from_buffer_copy(raw[off:off + 64])
        start = shstr.sh_offset + sh.sh_name
        end = raw.find(b"\x00", start)
        names.append(raw[start:end].decode("utf-8", "replace"))
    return names


def list_binary(raw: bytes, h: Elf64_Ehdr) -> None:
    """Print sections and segments with their indices."""
    print(f"ELF type: e_type={h.e_type}  e_shnum={h.e_shnum}  e_phnum={h.e_phnum}\n")
    print("SECTIONS (use the index [Nr] with --field sh_*):")
    names = section_names(raw, h)
    for i in range(h.e_shnum):
        off = h.e_shoff + i * h.e_shentsize
        sh = Elf64_Shdr.from_buffer_copy(raw[off:off + 64])
        t = SHT_NAMES.get(sh.sh_type, hex(sh.sh_type))
        print(f"  [{i:2}] {names[i]:18} {t:10} off={sh.sh_offset:#08x} "
              f"size={sh.sh_size:#x} entsize={sh.sh_entsize}")
    print("\nSEGMENTS (use the index with --field p_*):")
    for i in range(h.e_phnum):
        off = h.e_phoff + i * h.e_phentsize
        ph = Elf64_Phdr.from_buffer_copy(raw[off:off + 56])
        t = PT_NAMES.get(ph.p_type, hex(ph.p_type))
        risk = "" if ph.p_type != 1 else "  <- PT_LOAD: corrupting this usually breaks execution"
        print(f"  [{i:2}] {t:14} off={ph.p_offset:#08x} "
              f"filesz={ph.p_filesz:#x} memsz={ph.p_memsz:#x}{risk}")


def resolve_value(token: str, width: int) -> int:
    """Resolve a named or numeric value token to an integer for the given field width."""
    mask = (1 << (8 * width)) - 1
    named = {"zero": 0, "one": 1, "max": mask, "all_ones": mask,
             "maxsigned": (1 << (8 * width - 1)) - 1,
             "signbit": 1 << (8 * width - 1)}
    v = named[token] if token in named else int(token, 0)
    return v & mask


def abs_offset(h: Elf64_Ehdr, table: str, field_off: int, idx: int | None) -> int:
    """Compute the absolute file offset of a field in EHDR, SHT, or PHT."""
    if table == "EHDR":
        return field_off
    if table == "SHT":
        return h.e_shoff + idx * h.e_shentsize + field_off
    if table == "PHT":
        return h.e_phoff + idx * h.e_phentsize + field_off
    raise ValueError(table)


def quick_run(path: str, timeout: float = 5.0, extra_args: list = None):
    """Run a binary and return (returncode, stdout). Returns error strings on failure."""
    try:
        cmd = [os.path.abspath(path)] + (extra_args or [])
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return "TIMEOUT", b""
    except Exception as e:
        return f"ERROR:{e}", b""


# Main

def main() -> None:
    ap = argparse.ArgumentParser(description="Corrupt one ELF64 field in a copy of the binary.")
    ap.add_argument("binary")
    ap.add_argument("--list", action="store_true",
                    help="list sections and segments with their indices, then exit")
    ap.add_argument("--field", help="field name: e_shoff, sh_size, p_filesz, ...")
    ap.add_argument("--index", type=int, help="entry index (required for sh_/p_ fields)")
    ap.add_argument("--value", help="a single explicit value (zero|one|max|maxsigned|signbit "
                    "or an integer). If OMITTED, generates all 5 patterns at once.")
    ap.add_argument("--output", help="output file prefix (default: <binary>)")
    ap.add_argument("--run", action="store_true",
                    help="run original and modified binary and compare output (report only)")
    ap.add_argument("--valid", action="store_true",
                    help="in battery mode, only keep files that run identically "
                         "(discard no-ops and broken binaries)")
    args = ap.parse_args()

    raw = open(args.binary, "rb").read()
    h = read_ehdr(raw)

    if args.list:
        list_binary(raw, h)
        return

    if not args.field:
        ap.error("specify --field (or use --list)")

    prefix = next((p for p in PREFIX if args.field.startswith(p)), None)
    if prefix is None:
        ap.error(f"field '{args.field}' does not start with e_/sh_/p_")
    table, struct_type, risky = PREFIX[prefix]

    if not hasattr(struct_type, args.field):
        ap.error(f"'{args.field}' does not exist in {table}")
    if table in ("SHT", "PHT") and args.index is None:
        ap.error(f"{table} fields require --index")

    fld = getattr(struct_type, args.field)
    off = abs_offset(h, table, fld.offset, args.index)
    width = fld.size
    old = int.from_bytes(raw[off:off + width], "little")

    # Values to generate: single explicit (--value) or the full battery of 5 patterns.
    BATTERY = ["zero", "one", "max", "maxsigned", "signbit"]
    if args.value is not None:
        requests = [(args.value, resolve_value(args.value, width))]
    else:
        requests = [(lbl, resolve_value(lbl, width)) for lbl in BATTERY]

    out_prefix = args.output or args.binary
    idx_part = f"_{args.index}" if args.index is not None else ""
    target_label = f"{table}" + (f"[{args.index}]" if args.index is not None else "")

    print(f"field         : {args.field}  ({target_label})")
    print(f"offset        : {off:#x}  (width {width} bytes)")
    print(f"original value: {old:#x} ({old})")
    if risky:
        print("WARNING       : PHT field — the kernel reads this; may break execution.")
    print()

    needs_run = args.valid or args.run
    rc0, out0 = quick_run(args.binary) if needs_run else (None, None)

    fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[width]
    generated = 0
    for label, new in requests:
        new_hex = f"{new:#x}"

        # Filter 1: no-op. Identical value tests nothing.
        # (only applies in battery mode; explicit --value is always written)
        if args.value is None and new == old:
            print(f"  {label:10} new={new_hex:>20}  ->  SKIPPED (no-op = original value)")
            continue

        out_path = f"{out_prefix}.{args.field}{idx_part}_{label}"
        buf = bytearray(raw)
        struct.pack_into(fmt, buf, off, new)
        with open(out_path, "wb") as f:
            f.write(buf)
        os.chmod(out_path, 0o755)

        equal = None
        if needs_run:
            rc1, out1 = quick_run(out_path)
            equal = (rc0 == rc1 and out0 == out1)

        # Filter 2: broken execution (only with --valid, only in battery mode).
        if args.valid and args.value is None and not equal:
            os.remove(out_path)
            print(f"  {label:10} new={new_hex:>20}  ->  SKIPPED (breaks execution)")
            continue

        line = f"  {label:10} new={new_hex:>20}  ->  {out_path}"
        if equal is not None:
            line += f"   runs_equal={equal}"
        print(line)
        generated += 1

    print(f"\n{generated} valid binary(ies) generated for tool analysis.")


if __name__ == "__main__":
    main()