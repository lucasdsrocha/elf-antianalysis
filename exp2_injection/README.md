# Experiment 2 — Targeted Code Injection

## Overview

Three patchers inject arbitrary position-independent shellcode into an
already-compiled ELF binary without access to source code. Each patcher
targets a different binary type:

| Patcher | Strategy | Default output suffix | Applicable to |
|---|---|---|---|
| `patcher_ptnote.py` | PT_NOTE → PT_LOAD | `.patched` | ET_EXEC, ET_DYN executables |
| `patcher_newsegment.py` | PHT relocation + new PT_LOAD | `.newsegmentpatched` | ET_EXEC, ET_DYN executables |
| `patcher_so.py` | DT_INIT_ARRAY hijack | `.sopatched` | ET_DYN shared libraries |

All patchers wrap the payload in a register-preserving boilerplate that
saves all 15 GPRs (rax through r15) before the payload executes and
restores them afterwards, ensuring the original program's entry point
receives the expected register state.

## Payloads

Two payloads are provided:

- **Demo write** (`--demo-write N`): injects N bytes of `X` followed by
  a shellcode that prints them via the `write` syscall, then transfers
  control to the original entry point
- **INT 3** (`int3.bin`): a single `0xCC` byte that generates `SIGTRAP`
  (exit code 133) when executed outside a debugger — a basic
  anti-debugging technique

Custom payloads can be supplied via `--payload <file>`. The payload must
be **position-independent** x86-64 machine code. For executables, it must
return normally (no trailing `ret` or `jmp`) — the wrapper handles the
jump to the original entry point. For shared libraries (`patcher_so.py`),
the payload must end with `ret`.

## patcher_ptnote.py

Locates the first `PT_NOTE` entry in the PHT, overwrites it as `PT_LOAD`
pointing to the payload appended at the next page boundary after the end
of the file, and updates `e_entry`. Preserves `e_phnum` and all original
PHT offsets.

**Default output:** `<input>.patched` (same directory as input)

```bash
# Analyze injection limits — no modification, prints stats
python3 patcher_ptnote.py <binary>

# Demo payload (N bytes of 'X' + write shellcode)
python3 patcher_ptnote.py <binary> --demo-write 8
# output: <binary>.patched

# Custom payload file
python3 patcher_ptnote.py <binary> --payload int3.bin
# output: <binary>.patched

# Specify output path
python3 patcher_ptnote.py <binary> --demo-write 8 -o <output>

# Suppress log messages
python3 patcher_ptnote.py <binary> --demo-write 8 -q
```

## patcher_newsegment.py

Relocates the entire PHT to the end of the file (since no space is
available to extend it in place), adds a new `PT_LOAD` entry covering
the relocated PHT and the payload, and updates `e_phoff`, `e_phnum`,
and `e_entry`. Updates `PT_PHDR` if present so the dynamic linker can
locate the new PHT.

**Default output:** `<input>.newsegmentpatched` (same directory as input)

```bash
# Demo payload
python3 patcher_newsegment.py <binary> --demo-write 8
# output: <binary>.newsegmentpatched

# Custom payload file
python3 patcher_newsegment.py <binary> --payload int3.bin

# Specify output path
python3 patcher_newsegment.py <binary> --demo-write 8 -o <output>

# Suppress log messages
python3 patcher_newsegment.py <binary> --demo-write 8 -q
```

## patcher_so.py

For shared libraries where `e_entry` is not executed by the dynamic
linker. Prepends a shellcode pointer to `DT_INIT_ARRAY` and adds
`R_X86_64_RELATIVE` relocations so the dynamic linker correctly
rebases the pointer at load time regardless of ASLR. Original slot
relocations are replicated exactly to preserve symbolic relocations.

**Default output:** `<input>.sopatched` (same directory as input)

```bash
# Demo payload
python3 patcher_so.py <library.so> --demo-write 8
# output: <library.so>.sopatched

# Custom payload file
python3 patcher_so.py <library.so> --payload int3.bin

# Specify output path
python3 patcher_so.py <library.so> --demo-write 8 -o <output>

# Suppress log messages
python3 patcher_so.py <library.so> --demo-write 8 -q
```

## Output File Location

By default, all patchers write the output to the **same directory as
the input**, with a suffix appended:

| Patcher | Input | Output |
|---|---|---|
| `patcher_ptnote.py` | `targets/bin/alvo_exec` | `targets/bin/alvo_exec.patched` |
| `patcher_newsegment.py` | `targets/bin/alvo_exec` | `targets/bin/alvo_exec.newsegmentpatched` |
| `patcher_so.py` | `targets/bin/libexemplo.so` | `targets/bin/libexemplo.so.sopatched` |

Use `-o <path>` to write to a different location.

## Reproducing the Experiment

```bash
cd exp2_injection

# --- PT_NOTE strategy ---
python3 patcher_ptnote.py ../targets/bin/alvo_exec   --demo-write 8
python3 patcher_ptnote.py ../targets/bin/alvo_pie    --demo-write 8
python3 patcher_ptnote.py ../targets/bin/alvo_static --demo-write 8
python3 patcher_ptnote.py /usr/bin/bash              --demo-write 8 \
    -o /tmp/bash.patched

# Validate demo output
../targets/bin/alvo_exec.patched          # expected: XXXXXXXXola 42
../targets/bin/alvo_pie.patched           # expected: XXXXXXXXola 42
../targets/bin/alvo_static.patched        # expected: XXXXXXXXola 42
/tmp/bash.patched --version               # expected: XXXXXXXXGnu bash, version ...

# --- New segment strategy ---
python3 patcher_newsegment.py ../targets/bin/alvo_exec   --demo-write 8
python3 patcher_newsegment.py ../targets/bin/alvo_pie    --demo-write 8
python3 patcher_newsegment.py ../targets/bin/alvo_static --demo-write 8

# Validate
../targets/bin/alvo_exec.newsegmentpatched   # expected: XXXXXXXXola 42

# --- SO strategy ---
python3 patcher_so.py ../targets/bin/libexemplo.so        --demo-write 8
python3 patcher_so.py /usr/lib/x86_64-linux-gnu/libm.so.6 --demo-write 8 \
    -o /tmp/libm.sopatched

# Compile test program and validate SO injection
gcc ../targets/src/usa_exemplo.c -o /tmp/usa_exemplo \
    -L../targets/bin -lexemplo -Wl,-rpath,../targets/bin
LD_PRELOAD=../targets/bin/libexemplo.so.sopatched /tmp/usa_exemplo
# expected: XXXXXXXXhelper: 42, soma: 7

LD_PRELOAD=/tmp/libm.sopatched ../targets/bin/alvo_exec
# expected: XXXXXXXXola 42

# --- INT 3 payload (anti-debugging validation) ---
python3 patcher_ptnote.py ../targets/bin/alvo_exec --payload int3.bin
../targets/bin/alvo_exec.patched; echo "exit: $?"
# expected: Trace/breakpoint trap, exit: 133

# --- Analyze injection limits ---
python3 patcher_ptnote.py ../targets/bin/alvo_exec
python3 patcher_ptnote.py ../targets/bin/alvo_static
python3 patcher_ptnote.py /usr/bin/bash
```

## Dependencies

All patchers import from `exp1_strip/strip.py`. The path is resolved
automatically via `sys.path.insert` — run the patchers from any directory
as long as the repository structure is intact.