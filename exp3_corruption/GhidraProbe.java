// GhidraProbe.java — Ghidra headless postScript.
// Runs AFTER auto-analysis. Detects whether the binary was imported as ELF
// or raw binary, counts functions, and checks if at least one non-external
// function has a valid disassembled body.
//
// Prints a sentinel line that probe_ghidra (test_runner.py) reads:
//     GHIDRA_JSON {"func_count": N, "disasm_ok": true/false, "format": "elf"|"raw"}
//
// disasm_ok is true if at least one non-external function has a non-empty body,
// ensuring that imported symbols without bodies do not produce false negatives.
//
// The class name MUST match the file name (GhidraProbe).
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class GhidraProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("GHIDRA_JSON {\"func_count\": 0, \"disasm_ok\": false, \"format\": \"none\"}");
            return;
        }

        int n = currentProgram.getFunctionManager().getFunctionCount();

        // Detect whether the binary was imported as ELF or raw binary
        String fmt = currentProgram.getExecutableFormat();
        boolean isElf = fmt != null && fmt.toLowerCase().contains("elf");

        // Check if at least one non-external function has a valid disassembled body.
        // Skipping external functions avoids false negatives when the first function
        // in the iterator is an imported symbol without a body.
        boolean disasmOk = false;
        try {
            FunctionIterator funcs = currentProgram.getFunctionManager()
                    .getFunctions(true);
            while (funcs.hasNext()) {
                Function f = funcs.next();
                if (!f.isExternal() && f.getBody().getNumAddresses() > 0) {
                    disasmOk = true;
                    break;
                }
            }
        } catch (Exception e) {
            disasmOk = false;
        }

        println("GHIDRA_JSON {\"func_count\": " + n
                + ", \"disasm_ok\": " + disasmOk
                + ", \"format\": \"" + (isElf ? "elf" : "raw") + "\"}");
    }
}