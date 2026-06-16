#!/usr/bin/env python3
"""test_runner.py — break test battery.

Test unit: (set, value). For each test, ALL fields of ALL entries
(skipping index 0) in the target table(s) receive the same value,
respecting each field's width.

Sets:
  SHT  — all Elf64_Shdr entries + EHDR fields describing the SHT
         (e_shoff, e_shentsize, e_shnum, e_shstrndx)
  PHT  — surviving Elf64_Phdr entries (EHDR PHT fields excluded: always
         break execution)
  EHDR — safe EHDR fields: e_version, e_flags, e_ehsize + e_ident bytes
         4-15 (magic bytes 0-3 are preserved)
  ALL  — SHT + PHT + EHDR simultaneously

Values: zero (0), max, random (per field, reproducible via --seed).

PHT pre-modification rule: only applies to entries that do NOT break
execution. Each entry is tested as a whole (all fields filled); entries
that crash are skipped. The combined set is then revalidated.
The SHT and EHDR never break execution (the kernel ignores them).

Oracle results:
  GDB:    opened | broke
  Ghidra: opened_elf | opened_raw | broke
  (Ghidra attempts ELF import first; falls back to raw binary if needed)

Ephemeral binary (generated in /tmp and deleted). CSV written to results/.
Modified binaries saved to targets/bin/ with incremental index if --save.

Depends on degrade.py, gdb_extract.py (and GhidraProbe.java for Ghidra),
all in the same directory.

    python3 test_runner.py ./alvo_pie
    python3 test_runner.py ./alvo_pie --ghidra "$HOME/ghidra_12.1/support/analyzeHeadless"
    python3 test_runner.py ./alvo_pie --sets SHT PHT
    python3 test_runner.py /usr/bin/bash --args --version
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import resource
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from degrade import (
    Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, read_ehdr, abs_offset, quick_run,
)

VALUES     = ["zero", "max", "random"]
SETS       = ["SHT", "PHT", "EHDR", "ALL"]
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GDB_EXTRACT = os.path.join(SCRIPT_DIR, "gdb_extract.py")
_FMT = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}

# EHDR fields safe to corrupt (do not affect execution)
EHDR_SHT_FIELDS  = ("e_shoff", "e_shentsize", "e_shnum", "e_shstrndx")
EHDR_SAFE_FIELDS = ("e_version", "e_flags", "e_ehsize")
# e_ident bytes 4-15 (bytes 0-3 are the ELF magic and must not be touched)
EIDENT_CORRUPT_RANGE = (4, 16)


# Execution with resource caps

def _capped(cmd, timeout, env=None, as_limit=2 * 1024**3, cpu=20):
    def pre():
        if as_limit:
            resource.setrlimit(resource.RLIMIT_AS, (as_limit, as_limit))
        if cpu:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        os.setsid()
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           preexec_fn=pre, env=env)
        return p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired:
        return None, b"", b"", True


# Oracles

def _error_line(text, patterns, limit=200):
    for ln in text.splitlines():
        if any(p in ln.lower() for p in patterns):
            return " ".join(ln.split())[:limit]
    return ""


def probe_gdb(path, timeout=20):
    env = dict(os.environ, HARNESS_TARGET=os.path.abspath(path))
    rc, out, err, to = _capped(
        ["gdb", "-q", "-batch", "-nx", "-x", GDB_EXTRACT], timeout, env)
    if to:
        return "broke", "timeout"
    if rc is not None and rc < 0:
        return "broke", f"killed by signal {-rc}"
    metrics = None
    for line in out.decode("utf-8", "replace").splitlines():
        i = line.find("HARNESS_JSON ")
        if i >= 0:
            try:
                metrics = json.loads(line[i + len("HARNESS_JSON "):])
            except Exception:
                pass
            break
    if metrics is None:
        msg = _error_line(err.decode("utf-8", "replace"),
                          ("error", "exception", "fatal", "abort")) or "no response from gdb"
        return "broke", msg
    if not metrics.get("loaded"):
        msg = metrics.get("load_error") or _error_line(
            err.decode("utf-8", "replace"), ("error", "not in")) or "refused to load"
        return "broke", " ".join(str(msg).split())[:200]
    return "opened", ""


def _ghidra_import(path, ghidra_bin, projdir, timeout, extra_args=None):
    """Run Ghidra headless import. extra_args can force processor/cspec for raw mode.
    Uses a separate project directory for raw mode to avoid conflicts.
    For raw mode, copies the file with a .elf extension so Ghidra accepts it."""
    actual_projdir = projdir + "_raw" if extra_args else projdir
    import_path = path
    tmp_elf = None
    if extra_args:
        # Ghidra rejects files without recognised extensions in raw mode;
        # copy to a temp file with .elf suffix so the loader accepts it.
        fd, tmp_elf = tempfile.mkstemp(suffix=".elf")
        with os.fdopen(fd, "wb") as f:
            f.write(open(path, "rb").read())
        os.chmod(tmp_elf, 0o755)
        import_path = tmp_elf
    try:
        cmd = [ghidra_bin, actual_projdir, "p", "-import", os.path.abspath(import_path),
               "-scriptPath", SCRIPT_DIR, "-postScript", "GhidraProbe.java",
               "-deleteProject", "-overwrite",
               "-analysisTimeoutPerFile", str(int(timeout))]
        if extra_args:
            cmd.extend(extra_args)
        rc, out, err, to = _capped(cmd, timeout + 30, as_limit=None, cpu=None)
        text = out.decode("utf-8", "replace") + err.decode("utf-8", "replace")
        return to, text
    finally:
        if tmp_elf and os.path.exists(tmp_elf):
            os.unlink(tmp_elf)


def probe_ghidra(path, ghidra_bin, projdir, timeout=120):
    """Two-phase Ghidra oracle:
    Phase 1: attempt normal ELF import.
    Phase 2: if Phase 1 failed or produced no disassembly (including
             ProgramLoader errors), retry as raw x86-64 binary.

    Results:
      opened_elf — imported as ELF with valid disassembly
      opened_raw — only succeeded as raw binary
      broke      — failed or produced no disassembly in both modes
    """
    # Phase 1: normal ELF import
    to, text = _ghidra_import(path, ghidra_bin, projdir, timeout)
    if to:
        return "broke", "timeout"

    def _parse_ghidra_json(text):
        """Extract and parse the GHIDRA_JSON object from Ghidra output.
        Handles trailing content like (GhidraScript) after the JSON."""
        for line in text.splitlines():
            if "GHIDRA_JSON" in line:
                try:
                    start = line.index("{")
                    end   = line.rindex("}") + 1
                    return json.loads(line[start:end])
                except Exception:
                    pass
        return None

    data = _parse_ghidra_json(text)

    # Check if Phase 1 succeeded as ELF with valid disassembly
    if data is not None:
        fmt    = data.get("format", "")
        disasm = data.get("disasm_ok", False)
        funcs  = data.get("func_count", 0)
        if fmt == "elf" and disasm and funcs > 0:
            return "opened_elf", ""

    # Phase 1 did not produce opened_elf — always try raw binary fallback.
    # This covers: ProgramLoader errors, ELF recognised but no disassembly,
    # and any other failure mode.
    to2, text2 = _ghidra_import(path, ghidra_bin, projdir, timeout,
                                 extra_args=["-processor", "x86:LE:64:default",
                                             "-cspec", "gcc"])
    if to2:
        return "broke", "timeout (raw)"

    data2 = _parse_ghidra_json(text2)

    if data2 is not None:
        disasm2 = data2.get("disasm_ok", False)
        funcs2  = data2.get("func_count", 0)
        if disasm2 and funcs2 > 0:
            return "opened_raw", ""
        return "broke", f"raw: func_count={funcs2} disasm_ok={disasm2}"

    msg = _error_line(text + text2,
                      ("error", "exception", "import failed", "unable to", "cannot")) \
          or "disassembly failed in both modes"
    return "broke", msg


# Fill helpers

def make_fill(value):
    if value == "zero":
        return lambda w, key: 0
    if value == "max":
        return lambda w, key: (1 << (8 * w)) - 1
    cache = {}
    def f(w, key):
        if key not in cache:
            cache[key] = random.randrange(0, 1 << (8 * w))
        return cache[key]
    return f


def fill_entry(buf, h, table, struct_type, idx, fill):
    for fname, _ in struct_type._fields_:
        fld = getattr(struct_type, fname)
        if fld.size not in _FMT:
            continue
        off = abs_offset(h, table, fld.offset, idx)
        val = fill(fld.size, (table, idx, fld.offset)) & ((1 << (8 * fld.size)) - 1)
        struct.pack_into(_FMT[fld.size], buf, off, val)


def fill_ehdr_safe(buf, fill, is_lib=False):
    """Corrupt safe EHDR fields.
    For executables: e_version, e_flags, e_ehsize + e_ident[4:16].
    For shared libraries: e_flags and e_ehsize only.
    dlopen validates e_ident[4:16] and e_version for .so files,
    so corrupting them breaks loading rather than just analysis."""
    for fname in EHDR_SAFE_FIELDS:
        if is_lib and fname == "e_version":
            continue
        fld = getattr(Elf64_Ehdr, fname)
        val = fill(fld.size, ("EHDR_SAFE", 0, fld.offset))
        struct.pack_into(_FMT[fld.size], buf, fld.offset,
                         val & ((1 << (8 * fld.size)) - 1))
    # e_ident[4:16] only for executables
    if not is_lib:
        start, end = EIDENT_CORRUPT_RANGE
        for i in range(start, end):
            val = fill(1, ("EIDENT", 0, i)) & 0xFF
            buf[i] = val


def _dlopen_ok(path, timeout):
    code = (
        "import ctypes, os, sys\n"
        "ctypes.CDLL(sys.argv[1], mode=os.RTLD_LAZY)\n"
    )
    rc, out, err, to = _capped(
        ["python3", "-c", code, os.path.abspath(path)], timeout)
    return (not to) and rc == 0


def runs_equal(path, base_rc, base_out, timeout,
               is_lib=False, base_loads=None, extra_args=None):
    if is_lib:
        return _dlopen_ok(path, timeout) == base_loads
    rc, out = quick_run(path, timeout, extra_args or [])
    return rc == base_rc and out == base_out


def write_temp(buf):
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        f.write(buf)
    os.chmod(path, 0o755)
    return path


def save_binary(buf, binary_path, conjunto, valor, bin_out):
    """Save binary to targets/bin/ with incremental index to avoid overwriting."""
    stem, ext = os.path.splitext(os.path.basename(binary_path))
    base = os.path.join(bin_out, f"{stem}_{conjunto}_{valor}{ext}")
    if not os.path.exists(base):
        dest = base
    else:
        idx = 1
        while True:
            dest = os.path.join(bin_out, f"{stem}_{conjunto}_{valor}_{idx}{ext}")
            if not os.path.exists(dest):
                break
            idx += 1
    with open(dest, "wb") as bf:
        bf.write(buf)
    os.chmod(dest, 0o755)
    return dest


def discover_pht_survivors(raw, h, fill, base_rc, base_out, timeout,
                            is_lib=False, base_loads=None, extra_args=None):
    survivors = []
    for idx in range(1, h.e_phnum):
        buf = bytearray(raw)
        fill_entry(buf, h, "PHT", Elf64_Phdr, idx, fill)
        path = write_temp(buf)
        try:
            if runs_equal(path, base_rc, base_out, timeout, is_lib, base_loads,
                          extra_args=extra_args):
                survivors.append(idx)
        finally:
            os.unlink(path)
    return survivors


# Main

def main():
    ap = argparse.ArgumentParser(description="Break test battery (set x value).")
    ap.add_argument("binary")
    ap.add_argument("--sets", nargs="+", default=SETS,
                    choices=SETS, help="which sets to run")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--ghidra", help="path to analyzeHeadless; enables Ghidra oracle")
    ap.add_argument("--ghidra-proj", default="/tmp/gh_proj")
    ap.add_argument("--out", default="results")
    ap.add_argument("--save", action="store_true",
                    help="save tested binaries to targets/bin/ with incremental index")
    ap.add_argument("--bin-out", default="targets/bin")
    ap.add_argument("--seed", type=int, default=0, help="random seed")
    ap.add_argument("--args", nargs=argparse.REMAINDER, default=[],
                    help="additional arguments to pass to the binary")
    args = ap.parse_args()

    random.seed(args.seed)
    raw = open(args.binary, "rb").read()
    h = read_ehdr(raw)

    is_lib = (os.path.basename(args.binary).endswith(".so") or
              ".so." in os.path.basename(args.binary))

    base_rc, base_out, base_loads = None, None, None
    if is_lib:
        base_loads = _dlopen_ok(args.binary, args.timeout)
        if not base_loads:
            raise SystemExit("Original library does not load via dlopen.")
    else:
        base_rc, base_out = quick_run(args.binary, args.timeout, args.args)
        if isinstance(base_rc, str):
            raise SystemExit(f"Original binary does not run cleanly (rc={base_rc}).")

    ghidra = None
    if args.ghidra:
        os.makedirs(args.ghidra_proj, exist_ok=True)
        os.makedirs(args.ghidra_proj + "_raw", exist_ok=True)
        ghidra = (args.ghidra, args.ghidra_proj)

    os.makedirs(args.out, exist_ok=True)
    if args.save:
        os.makedirs(args.bin_out, exist_ok=True)

    rows = []
    for conjunto in args.sets:
        usa_sht  = conjunto in ("SHT", "ALL")
        usa_pht  = conjunto in ("PHT", "ALL")
        usa_ehdr = conjunto in ("EHDR", "ALL")

        for valor in VALUES:
            fill = make_fill(valor)
            row = {"set": conjunto, "value": valor,
                   "target": os.path.basename(args.binary),
                   "sht_entries": "", "pht_entries": "",
                   "pht_survivors": "", "pht_skipped": "", "status": "",
                   "gdb": "empty", "gdb_error": "",
                   "ghidra": "empty", "ghidra_error": ""}

            survivors = None
            if usa_pht:
                survivors = discover_pht_survivors(
                    raw, h, fill, base_rc, base_out, args.timeout,
                    is_lib, base_loads, extra_args=args.args)
                skipped = [i for i in range(1, h.e_phnum) if i not in survivors]
                row["pht_entries"]   = h.e_phnum - 1
                row["pht_survivors"] = len(survivors)
                row["pht_skipped"]   = "[" + ",".join(map(str, skipped)) + "]"

            buf = bytearray(raw)

            if usa_sht:
                row["sht_entries"] = h.e_shnum - 1
                for i in range(1, h.e_shnum):
                    fill_entry(buf, h, "SHT", Elf64_Shdr, i, fill)
                for fname in EHDR_SHT_FIELDS:
                    fld = getattr(Elf64_Ehdr, fname)
                    val = fill(fld.size, ("EHDR_SHT", 0, fld.offset))
                    struct.pack_into(_FMT[fld.size], buf, fld.offset,
                                     val & ((1 << (8 * fld.size)) - 1))

            if usa_pht:
                for i in survivors:
                    fill_entry(buf, h, "PHT", Elf64_Phdr, i, fill)

            if usa_ehdr:
                fill_ehdr_safe(buf, fill, is_lib=is_lib)

            if bytes(buf) == raw:
                row["status"] = ("no_pht_survivors"
                                 if usa_pht and not survivors and not usa_sht
                                 else "no-op")
                rows.append(row)
                continue

            path = write_temp(buf)
            try:
                if not runs_equal(path, base_rc, base_out, args.timeout,
                                  is_lib, base_loads, extra_args=args.args):
                    row["status"] = "set_broke"
                    rows.append(row)
                    continue

                row["status"] = "tested"
                row["gdb"], row["gdb_error"] = probe_gdb(path)
                if ghidra is not None:
                    row["ghidra"], row["ghidra_error"] = probe_ghidra(
                        path, ghidra[0], ghidra[1])
            finally:
                os.unlink(path)

            if args.save:
                save_binary(bytes(buf), args.binary, conjunto, valor, args.bin_out)

            rows.append(row)

    cols = ["set", "value", "target", "sht_entries", "pht_entries",
            "pht_survivors", "pht_skipped", "status",
            "gdb", "gdb_error", "ghidra", "ghidra_error"]
    csv_path = os.path.join(args.out, f"{os.path.basename(args.binary)}.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    broke = [r for r in rows if r["gdb"] == "broke" or "broke" in r["ghidra"]]
    print(f"{len(rows)} tests | {len(broke)} BROKE at least one tool")
    print(f"CSV: {csv_path}\n")
    print(f"{'set':9} {'value':10} {'status':22} {'gdb':9} ghidra")
    for r in rows:
        print(f"  {r['set']:9} {r['value']:10} {r['status']:22} "
              f"{r['gdb']:9} {r['ghidra']}")


if __name__ == "__main__":
    main()