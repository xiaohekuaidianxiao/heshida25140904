import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class FuncXrefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        try {
            println("SCRIPT_START: FuncXrefs");
            String[] args = getScriptArgs();
            if (args == null || args.length < 1) {
                println("ERROR: Need function name as argument");
                return;
            }
            String funcName = args[0];
            println("Looking up function: " + funcName);

            Listing listing = currentProgram.getListing();
            Function func = listing.getFunction(funcName);

            if (func == null) {
                SymbolTable st = currentProgram.getSymbolTable();
                SymbolIterator si = st.getSymbols(funcName);
                while (si.hasNext()) {
                    Symbol sym = si.next();
                    if (sym.isFunction()) {
                        func = listing.getFunctionAt(sym.getAddress());
                        if (func != null) break;
                    }
                }
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

            println("Analyzing xrefs to: " + func.getName() + " @ " + func.getEntryPoint());
            Set<String> callers = new TreeSet<>();
            Reference[] refs = currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint());
            for (Reference ref : refs) {
                Function caller = listing.getFunctionContaining(ref.getFromAddress());
                if (caller != null) callers.add(caller.getName());
            }
            if (callers.isEmpty()) {
                println("No cross references found.");
            } else {
                println("Called by: " + String.join(", ", callers));
            }
        } catch (Exception e) {
            println("EXCEPTION: " + e.getClass().getName() + ": " + e.getMessage());
        }
    }
}

