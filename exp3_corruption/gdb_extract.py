"""gdb_extract.py — runs INSIDE gdb:
        gdb -q -batch -nx -x gdb_extract.py

The target binary is provided via the HARNESS_TARGET environment variable,
so the same script works for any binary, clean or corrupted.

Prints ONE line to stdout:
        HARNESS_JSON {...metrics...}
The test runner reads this line and compares the metrics of the corrupted
binary against those of the clean original to determine the break level.

Why GDB Python (instead of parsing raw GDB text output): the embedded `gdb`
module executes commands and returns output as stable strings, and `gdb.error`
signals load refusal cleanly.
"""
import gdb
import os
import re
import json

target = os.environ["HARNESS_TARGET"]
HEX = re.compile(r"0x[0-9a-fA-F]+")

m = {
    "loaded":        False,  # did GDB accept the file?
    "func_count":    0,      # how many functions/symbols it could see (.symtab via SHT)
    "section_count": 0,      # how many sections (read from SHT via BFD)
    "disasm_ok":     False,  # could it disassemble the entry point?
    "load_error":    None,   # error message if the file was rejected
}

# 1. Attempt to load. If the SHT is corrupted enough for BFD to reject the
#    file, this raises gdb.error -> classified as a break.
try:
    gdb.execute(f"file {target}", to_string=True)
    m["loaded"] = True
except gdb.error as e:
    m["load_error"] = str(e)

if m["loaded"]:
    # 2. Symbol view: comes from .symtab, located via the SHT.
    try:
        out = gdb.execute("info functions", to_string=True)
        m["func_count"] = len(HEX.findall(out))
    except gdb.error as e:
        m["func_error"] = str(e)

    # 3. Section view: read from the SHT via BFD. More sensitive probe.
    #    'maintenance info sections' is what this GDB version accepts
    #    ('info sections' is not available).
    try:
        out = gdb.execute("maintenance info sections", to_string=True)
        m["section_count"] = len(HEX.findall(out))
    except gdb.error as e:
        m["section_error"] = str(e)

    # 4. Can it disassemble the entry point? (tries main first, then _start)
    for sym in ("main", "_start"):
        try:
            gdb.execute(f"disassemble {sym}", to_string=True)
            m["disasm_ok"] = True
            break
        except gdb.error as e:
            m["disasm_error"] = str(e)

print("HARNESS_JSON " + json.dumps(m))