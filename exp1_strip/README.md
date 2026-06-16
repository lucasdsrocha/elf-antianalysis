# Experiment 1 — Symbolic Metadata Removal

## Overview

`strip.py` implements a custom ELF strip operation that removes all
sections not mapped into memory at runtime. The selection criterion is
the `SHF_ALLOC` flag in `sh_flags`: sections without this flag do not
reside within a `PT_LOAD` segment and can be discarded without affecting
execution.

The key difference from `binutils strip --strip-all` is that this
implementation also removes `.comment` (compiler toolchain metadata),
which the Binutils strip preserves by default.

## How It Works

The implementation follows a three-phase pipeline:

1. **Parse** — reads the ELF Header, PHT, and SHT into memory using
   `ctypes` representations of `Elf64_Ehdr`, `Elf64_Shdr`, and `Elf64_Phdr`
2. **Transform** — evaluates each `Elf64_Shdr` entry against `SHF_ALLOC`:
   entries with the flag are retained; entries without it are discarded
3. **Serialize** — writes the original bytes up to the end of the last
   `PT_LOAD` segment, appends a reconstructed `.shstrtab`, and writes a
   minimal SHT; updates `e_shoff`, `e_shnum`, and `e_shstrndx` in the EHDR

## Usage

```bash
# Strip a binary — output saved as <input>.stripped in the same directory
python3 strip.py <binary>

# Example: targets/bin/alvo_exec → targets/bin/alvo_exec.stripped
python3 strip.py targets/bin/alvo_exec

# Specify a custom output path
python3 strip.py <binary> -o <output>

# Overwrite the original file in place
python3 strip.py <binary> --in-place

# Verbose mode (shows which sections are removed and the output size)
python3 strip.py <binary> -v
```

## Reproducing the Experiment

```bash
cd exp1_strip

# Purpose-built binaries
# Output: targets/bin/alvo_exec.stripped, etc.
python3 strip.py ../targets/bin/alvo_exec    -v
python3 strip.py ../targets/bin/alvo_pie     -v
python3 strip.py ../targets/bin/alvo_static  -v
python3 strip.py ../targets/bin/libexemplo.so -v

# System binaries (already stripped by the distribution)
# Output: /usr/bin/bash.stripped, /usr/lib/.../libm.so.6.stripped
# Note: use -o to write to a writable location
python3 strip.py /usr/bin/bash \
    -o /tmp/bash.stripped -v
python3 strip.py /usr/lib/x86_64-linux-gnu/libm.so.6 \
    -o /tmp/libm.stripped -v

# Validate execution is preserved
../targets/bin/alvo_exec.stripped          # expected: ola 42
../targets/bin/alvo_pie.stripped           # expected: ola 42
../targets/bin/alvo_static.stripped        # expected: ola 42

# Confirm stripped status
file ../targets/bin/alvo_exec.stripped
readelf -S ../targets/bin/alvo_exec.stripped
```

## Output File Location

By default, the stripped binary is written to the **same directory as
the input**, with `.stripped` appended to the filename:

| Input | Output |
|---|---|
| `targets/bin/alvo_exec` | `targets/bin/alvo_exec.stripped` |
| `targets/bin/libexemplo.so` | `targets/bin/libexemplo.so.stripped` |
| `/usr/bin/bash` | `/usr/bin/bash.stripped` *(requires write permission)* |

For system binaries or read-only locations, use `-o` to specify a
writable output path.

## Using with Other Binaries

`strip.py` works on any ELF64 binary:

```bash
python3 strip.py /path/to/binary -v
python3 strip.py /path/to/binary -o /path/to/output -v
```

Note that `strip.py` also serves as the shared module for Experiments 2
and 3, which import `ElfFile`, `Elf64_Ehdr`, `Elf64_Phdr`, `Elf64_Shdr`,
and `quick_run` from it.
