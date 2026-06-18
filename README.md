# ELF Binary Anti-Analysis Techniques

This repository contains the implementation and experimental data for the
thesis *"Experimental Study of Anti-Debugging Techniques in Linux
Environments"* (IDP, 2025).

The work evaluates three post-build anti-analysis techniques applied to
ELF64 binaries on x86-64 Linux, without access to source code or
recompilation. The fundamental constraint shared by all three techniques
is that the modified binary must execute identically to the original.

## Techniques

| Experiment | Technique | Directory |
|---|---|---|
| 1 | Symbolic metadata removal | `exp1_strip/` |
| 2 | Targeted code injection | `exp2_injection/` |
| 3 | ELF structural metadata corruption | `exp3_corruption/` |

## Repository Structure

```
codigos/
├── exp1_strip/          Symbolic metadata removal
├── exp2_injection/      Code injection into compiled binaries
├── exp3_corruption/     ELF structural metadata corruption
├── targets/
│   ├── src/             C source files for purpose-built binaries
│   └── bin/             Compiled target binaries
└── results/             CSV results from Experiment 3
```

## Dependencies

All scripts require **Python 3.10+** and run on **Linux x86-64**.

```bash
# Required system tools
sudo apt install gdb binutils

# Required for Experiment 3 (Ghidra oracle)
# Download Ghidra from https://ghidra-sre.org/ and note the path to
# support/analyzeHeadless
```

No Python packages beyond the standard library are required.

## Target Binaries

The `targets/bin/` directory contains four pre-compiled purpose-built
binaries. To recompile them from source:

```bash
cd targets/src

gcc -g -no-pie -o ../bin/alvo_exec teste.c
gcc -g -o ../bin/alvo_pie teste.c
gcc -g -static -o ../bin/alvo_static teste.c
gcc -g -shared -fPIC -o ../bin/libexemplo.so lib_t.c
```

System binaries `/usr/bin/bash` and `/usr/lib/x86_64-linux-gnu/libm.so.6`
are used as additional targets in Experiments 1 and 3. They are not
included in the repository and are read directly from the system path.

## Environment

The experiments were developed and validated on:

- OS: Ubuntu 26.04 LTS via WSL2 (Windows 11)
- Kernel: 6.6.87.2-microsoft-standard-WSL2
- Python: 3.14.4
- GCC: 15.2.0
- GDB: 17.1
- Ghidra: 12.1
- IDA Free: 9.0
- GNU Binutils: 2.46

## Results

The `results/` directory contains the CSV output from Experiment 3 for
all six target binaries. Each file follows the naming convention
`<binary_name>.csv` and includes columns for modification set, fill
value, GDB result, and Ghidra result.
