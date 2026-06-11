import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileFunc extends GhidraScript {
    @Override
    public void run() throws Exception {
        try {
            println("SCRIPT_START: DecompileFunc");
            String[] args = getScriptArgs();
            if (args == null || args.length < 1) {
                println("ERROR: Need function name as argument");
                return;
            }
            String funcName = args[0];
            println("Looking up function: " + funcName);

            Listing listing = currentProgram.getListing();
            Function func = listing.getFunction(funcName);

            // If not found by name, try symbol table search
            if (func == null) {
                println("Not found by listing name, trying symbol table...");
                SymbolTable st = currentProgram.getSymbolTable();
                SymbolIterator si = st.getSymbols(funcName);
                while (si.hasNext()) {
                    Symbol sym = si.next();
                    if (sym.isFunction()) {
                        func = listing.getFunctionAt(sym.getAddress());
                        if (func != null) {
                            println("Found via symbol: " + func.getName() + " @ " + func.getEntryPoint());
                            break;
                        }
                    }
                }
            } else {
                println("Found function: " + func.getName() + " @ " + func.getEntryPoint());
            }

            if (func == null) {
                println("ERROR: Function '" + funcName + "' not found.");
                println("Available user-defined functions:");
                FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
                int count = 0;
                while (fi.hasNext() && count < 30) {
                    Function f = fi.next();
                    if (!f.isExternal()) {
                        println("  " + f.getEntryPoint() + " " + f.getName());
                        count++;
                    }
                }
                return;
            }

            println("Decompiling...");
            DecompInterface dc = new DecompInterface();
            dc.openProgram(currentProgram);
            DecompileResults dr = dc.decompileFunction(func, 60, new ConsoleTaskMonitor());
            if (dr != null && dr.decompileCompleted()) {
                println("DECOMPILED_CODE_START");
                println(dr.getDecompiledFunction().getC());
                println("DECOMPILED_CODE_END");
            } else {
                String err = (dr != null) ? dr.getErrorMessage() : "unknown";
                println("ERROR: Decompilation failed: " + err);
            }
            dc.dispose();
        } catch (Exception e) {
            println("EXCEPTION: " + e.getClass().getName() + ": " + e.getMessage());
        }
    }
}

