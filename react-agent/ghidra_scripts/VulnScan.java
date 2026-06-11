import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.Address;
import java.util.*;

public class VulnScan extends GhidraScript {

    private static final String[] SINKS = {
        "gets", "fgets", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "__strcpy_chk", "__strcat_chk",
        "__sprintf_chk", "__snprintf_chk",
        "scanf", "sscanf", "fscanf",
        "system", "popen", "execl", "execlp", "execle",
        "execv", "execvp", "execvpe",
        "memcpy", "memmove", "memset",
        "read", "recv", "recvfrom"
    };

    private static final String[] SOURCE_SINKS = {
        "gets", "fgets", "scanf", "sscanf", "fscanf",
        "read", "recv", "recvfrom"
    };

    @Override
    public void run() throws Exception {
        println("=== VulnScan: Dangerous Function Call Scan ===");
        println("Program: " + currentProgram.getName());
        println("Image base: " + currentProgram.getImageBase());
        println("NOTE: Binary is stripped. Ghidra auto-names functions as ENTRYADDR.");
        println("Use these names when calling ghidra_decompile_function or ghidra_get_function_calls.");
        println("");

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();

        Map<String, List<String[]>> findings = new LinkedHashMap<>();

        FunctionIterator funcs = fm.getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            InstructionIterator insts = listing.getInstructions(func.getBody(), true);
            while (insts.hasNext()) {
                Instruction ins = insts.next();
                String m = ins.getMnemonicString().toLowerCase();
                if (!m.equals("call") && !m.equals("callq") && !m.equals("jmp")) {
                    continue;
                }

                Reference[] refs = ins.getReferencesFrom();
                for (Reference ref : refs) {
                    Function tf = listing.getFunctionContaining(ref.getToAddress());
                    if (tf == null) continue;
                    String tn = tf.getName();

                    String matched = null;
                    for (String s : SINKS) {
                        if (tn.contains(s)) {
                            matched = s;
                            break;
                        }
                    }
                    if (matched == null) continue;

                    boolean isSrc = false;
                    for (String s : SOURCE_SINKS) {
                        if (tn.contains(s)) {
                            isSrc = true;
                            break;
                        }
                    }
                    String tag = isSrc ? "INPUT" : "SINK";

                    findings.computeIfAbsent(func.getName(), k -> new ArrayList<>())
                        .add(new String[]{
                            ins.getAddress().toString(),
                            tn,
                            tag
                        });
                }
            }
        }

        if (findings.isEmpty()) {
            println("No dangerous function calls found.");
            println("=== End VulnScan ===");
            return;
        }

        int totalFindings = 0;
        for (List<String[]> v : findings.values()) totalFindings += v.size();
        println("Found " + findings.size() + " functions with " + totalFindings + " dangerous calls:");
        println("");

        for (Map.Entry<String, List<String[]>> entry : findings.entrySet()) {
            String funcName = entry.getKey();
            List<String[]> calls = entry.getValue();

            Function func = null;
            FunctionIterator fi = fm.getFunctions(true);
            while (fi.hasNext()) {
                Function f = fi.next();
                if (f.getName().equals(funcName)) {
                    func = f;
                    break;
                }
            }
            if (func == null) continue;

            println("--- Function: " + funcName + " @ " + func.getEntryPoint() + " ---");
            println("  Dangerous calls: " + calls.size());
            for (String[] c : calls) {
                println("    [" + c[2] + "] " + c[1] + " called at " + c[0]);
            }

            List<Instruction> allInsts = new ArrayList<>();
            InstructionIterator iter = listing.getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                allInsts.add(iter.next());
            }

            Set<Integer> dangerIdx = new TreeSet<>();
            for (int i = 0; i < allInsts.size(); i++) {
                String addr = allInsts.get(i).getAddress().toString();
                for (String[] c : calls) {
                    if (addr.equals(c[0])) {
                        dangerIdx.add(i);
                        break;
                    }
                }
            }

            if (!dangerIdx.isEmpty()) {
                int minIdx = Collections.min(dangerIdx);
                int maxIdx = Collections.max(dangerIdx);
                int start = Math.max(0, minIdx - 8);
                int end = Math.min(allInsts.size() - 1, maxIdx + 8);

                println("  Instruction context (" + allInsts.size() + " total instructions):");
                for (int i = start; i <= end; i++) {
                    Instruction ins = allInsts.get(i);
                    String marker = dangerIdx.contains(i) ? " >>> " : "     ";
                    println("    " + marker + ins.getAddress() + " " + ins.toString());
                }
            }
            println("");
        }
        println("=== End VulnScan ===");
    }
}

