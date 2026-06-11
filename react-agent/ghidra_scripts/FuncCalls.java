import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class FuncCalls extends GhidraScript {
    @Override
    public void run() throws Exception {
        try {
            println("SCRIPT_START: FuncCalls");
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

            println("Analyzing calls in: " + func.getName() + " @ " + func.getEntryPoint());
            Set<String> calls = new TreeSet<>();
            InstructionIterator it = listing.getInstructions(func.getBody(), true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                String m = ins.getMnemonicString().toLowerCase();
                if (m.equals("call") || m.equals("callq") || m.equals("jmp")) {
                    for (Reference ref : ins.getReferencesFrom()) {
                        Function cf = listing.getFunctionContaining(ref.getToAddress());
                        if (cf != null) calls.add(cf.getName());
                    }
                }
            }
            if (calls.isEmpty()) {
                println("No calls found.");
            } else {
                println("Called functions: " + String.join(", ", calls));
            }
        } catch (Exception e) {
            println("EXCEPTION: " + e.getClass().getName() + ": " + e.getMessage());
        }
    }
}

