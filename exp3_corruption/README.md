# Experiment 3 — ELF Structural Metadata Corruption

## Overview

This experiment systematically corrupts ELF structural metadata fields to
degrade the ability of analysis tools to load and parse binaries, while
preserving execution behavior. Two tools are provided:

- **`degrade.py`** — corrupts a single field in a single binary for
  manual inspection. Self-contained: does not import `strip.py`.
- **`test_runner.py`** — runs a full automated battery across all
  modification sets and values, submitting results to GDB and Ghidra.

Supporting files:
- **`gdb_extract.py`** — GDB Python script used as the GDB oracle harness.
  Run by `test_runner.py` automatically; do not invoke directly.
- **`GhidraProbe.java`** — Ghidra postScript used as the Ghidra oracle.
  Must be in the same directory as `test_runner.py`. Ghidra compiles it
  automatically at runtime; no manual compilation needed.

## Modification Sets

| Set | Fields corrupted |
|---|---|
| `SHT` | All `Elf64_Shdr` entries + EHDR SHT fields (`e_shoff`, `e_shentsize`, `e_shnum`, `e_shstrndx`) |
| `PHT` | Surviving `Elf64_Phdr` entries (per-entry discovery phase excludes entries that break execution) |
| `EHDR` | Safe EHDR fields — executables: `e_version`, `e_flags`, `e_ehsize`, `e_ident[4:15]`; libraries: `e_flags`, `e_ehsize` only |
| `ALL` | SHT + PHT + EHDR simultaneously |

## Fill Values

| Value | Description |
|---|---|
| `zero` | All fields set to 0 |
| `one` | All fields set to 1 (degrade.py only) |
| `max` | All fields set to maximum unsigned value for their width |
| `maxsigned` | All fields set to maximum signed value (degrade.py only) |
| `signbit` | Sign bit set for each field width (degrade.py only) |
| `random` | Per-field pseudorandom values, reproducible via `--seed` (test_runner.py only) |

---

## degrade.py — Single Field Corruption

Corrupts one field of one entry and writes modified copies for manual
analysis. The original binary is never modified.

**Output files** are named `<binary>.<field>_<index>_<value>` and written
to the **same directory as the input binary** (or the path specified via
`--output`).

```
targets/bin/alvo_exec  →  targets/bin/alvo_exec.sh_size_5_max
                           targets/bin/alvo_exec.sh_size_5_zero
                           targets/bin/alvo_exec.sh_size_5_one
                           ...
```

### Usage

```bash
# List all sections and segments with their indices
python3 degrade.py <binary> --list

# Corrupt a single field — generates all 5 fill values
python3 degrade.py <binary> --field sh_size --index 5
# output: <binary>.sh_size_5_zero, .sh_size_5_one, .sh_size_5_max, ...

# Single explicit value
python3 degrade.py <binary> --field sh_size --index 5 --value max

# EHDR fields (no --index required)
python3 degrade.py <binary> --field e_shoff
python3 degrade.py <binary> --field e_shoff --value zero

# Compare execution output between original and modified
python3 degrade.py <binary> --field sh_size --index 5 --run

# Generate only files that execute identically to the original
python3 degrade.py <binary> --field p_filesz --index 2 --valid

# Write output to a specific prefix
python3 degrade.py <binary> --field sh_size --index 5 --output /tmp/test
# output: /tmp/test.sh_size_5_zero, /tmp/test.sh_size_5_max, ...
```

### Field naming

- `e_*` fields — EHDR (no `--index` required)
- `sh_*` fields — SHT entry (requires `--index <section_number>`)
- `p_*` fields — PHT entry (requires `--index <segment_number>`)

Use `--list` to see available indices for each binary.

---

## test_runner.py — Automated Battery

Runs all combinations of (set × value) on a binary, validates that each
modified binary executes identically to the original, and submits passing
binaries to GDB and Ghidra for analysis. Results are written to
`results/<binary_name>.csv`.

Modified binaries are ephemeral by default (created in `/tmp` and deleted
after testing). Use `--save` to keep them in `targets/bin/` with an
incremental index suffix.

```bash
# Run all sets with GDB oracle only
python3 test_runner.py <binary> --timeout 5

# Run with Ghidra oracle (recommended)
python3 test_runner.py <binary> \
    --ghidra /path/to/ghidra/support/analyzeHeadless \
    --timeout 5

# Run specific sets only
python3 test_runner.py <binary> --sets SHT EHDR --timeout 5

# Save modified binaries to targets/bin/ for manual inspection
python3 test_runner.py <binary> --save --timeout 5

# Reproducible random values (default seed: 0)
python3 test_runner.py <binary> --seed 42 --timeout 5

# Binary that requires arguments to terminate (e.g. bash)
python3 test_runner.py /usr/bin/bash --args --version --timeout 5

# Specify output directory for CSV results
python3 test_runner.py <binary> --out /path/to/results --timeout 5
```

### Ghidra two-phase oracle

`test_runner.py` uses a two-phase Ghidra oracle implemented in
`GhidraProbe.java`:

1. **Phase 1** — import as ELF normally. If `GhidraProbe.java` reports
   `disasm_ok=true` and `func_count > 0` with `format=elf`, result is
   `opened_elf`.
2. **Phase 2** — if phase 1 fails or produces no disassembly, retry as
   raw x86-64 (`x86:LE:64:default`, `gcc` calling convention). If
   disassembly succeeds, result is `opened_raw`. Otherwise, `broke`.

`GhidraProbe.java` checks:
- `func_count` — total functions identified
- `disasm_ok` — whether at least one **non-external** function has a
  valid disassembled body (skips imported symbols without bodies)
- `format` — whether Ghidra imported the binary as `elf` or `raw`

### GDB oracle

`gdb_extract.py` runs inside GDB via `gdb -q -batch -nx -x gdb_extract.py`
with the target binary path in the `HARNESS_TARGET` environment variable.
It reports:
- `loaded` — whether GDB accepted the binary
- `func_count` — functions visible via `.symtab`
- `section_count` — sections read from the SHT via BFD
- `disasm_ok` — whether `main` or `_start` could be disassembled
- `load_error` — error message if the binary was rejected

---

## Reproducing the Experiment

```bash
cd exp3_corruption
GHIDRA=~/ghidra_12.1/support/analyzeHeadless

# Purpose-built executables
python3 test_runner.py ../targets/bin/alvo_exec \
    --sets SHT PHT EHDR ALL --ghidra $GHIDRA --timeout 5

python3 test_runner.py ../targets/bin/alvo_pie \
    --sets SHT PHT EHDR ALL --ghidra $GHIDRA --timeout 5

python3 test_runner.py ../targets/bin/alvo_static \
    --sets SHT PHT EHDR ALL --ghidra $GHIDRA --timeout 5

# Shared library
python3 test_runner.py ../targets/bin/libexemplo.so \
    --sets SHT PHT EHDR ALL --ghidra $GHIDRA --timeout 5

# System binaries
python3 test_runner.py /usr/bin/bash \
    --sets SHT PHT EHDR ALL --ghidra $GHIDRA --timeout 5 \
    --args --version

python3 test_runner.py /usr/lib/x86_64-linux-gnu/libm.so.6 \
    --sets SHT PHT EHDR --ghidra $GHIDRA --timeout 5
```

---

## CSV Output Format

Results are written to `results/<binary_name>.csv`:

| Column | Description |
|---|---|
| `set` | Modification set (`SHT`, `PHT`, `EHDR`, `ALL`) |
| `value` | Fill value (`zero`, `max`, `random`) |
| `target` | Binary filename |
| `sht_entries` | Number of SHT entries corrupted |
| `pht_entries` | Total PHT entries tested in discovery phase |
| `pht_survivors` | PHT entries that passed discovery (do not break execution) |
| `pht_skipped` | Indices of PHT entries excluded from the test |
| `status` | `tested` / `set_broke` / `no_pht_survivors` / `no-op` |
| `gdb` | `opened` / `broke` |
| `gdb_error` | GDB error message if broke |
| `ghidra` | `opened_elf` / `opened_raw` / `broke` / `empty` |
| `ghidra_error` | Ghidra error message if broke |

---

## Using with Other Binaries

```bash
# Inspect field layout
python3 degrade.py /path/to/binary --list

# Run automated battery
python3 test_runner.py /path/to/binary \
    --sets SHT PHT EHDR ALL \
    --ghidra /path/to/analyzeHeadless \
    --timeout 5

# For shared libraries (.so detected automatically by filename)
python3 test_runner.py /path/to/library.so \
    --sets SHT PHT EHDR \
    --ghidra /path/to/analyzeHeadless \
    --timeout 5
```

Libraries (`.so` or `.so.` in filename) are detected automatically.
The executability oracle switches to `dlopen` for libraries. For shared
libraries, the `EHDR` set is restricted to `e_flags` and `e_ehsize` only,
since `dlopen` validates `e_ident[4:15]` and `e_version`.

For binaries that require arguments to terminate:
```bash
python3 test_runner.py /path/to/binary --args <arg1> <arg2> --timeout 5
```