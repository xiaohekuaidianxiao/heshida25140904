#!/usr/bin/env python3
"""
ReAct Agent for Static Binary Analysis
改进版：VulnScan 预扫描 + 证据链约束 + 增强错误处理
"""

import os
import sys
import json
import subprocess
import tempfile
import shutil
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from openai import OpenAI

# ==================== 配置区域 ====================
API_KEY = "sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
BASE_URL = "https://api.xiaomimimo.com/v1"
MODEL_NAME = "xiaomi/mimo-v2.5-pro"

GHIDRA_HOME = os.environ.get("GHIDRA_INSTALL_DIR", "/usr/share/ghidra")
GHIDRA_HEADLESS = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")

TARGET_FILE = "./targets/challenge"
LOG_FILE = "./logs/run.txt"
OUTPUT_FILE = "./output/vuln.json"

# Java 脚本存放目录
GHIDRA_SCRIPTS_DIR = "/tmp/ghidra_agent_java_scripts"


# ==================== Radare2 工具 ====================
class Radare2Tool:
    """radare2 工具封装"""

    def __init__(self):
        self.check_r2()
        print("[*] Radare2 tool initialized.")

    def check_r2(self):
        try:
            subprocess.run(["r2", "-v"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("radare2 (r2) not found in PATH")

    def _run_r2_command(self, binary_path: str, commands: List[str]) -> str:
        cmd = ["r2", "-q", "-c", ";".join(commands), binary_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "Error: Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"

    def get_functions_info(self, binary_path: str) -> str:
        print("[r2] Getting function list...")
        return self._run_r2_command(binary_path, ["aaa", "afl"])

    def disassemble_function(self, binary_path: str, func_name: str) -> str:
        print(f"[r2] Disassembling function: {func_name}")
        return self._run_r2_command(binary_path, ["aaa", f"s {func_name}", "pdf"])

    def decompile_function(self, binary_path: str, func_name: str) -> str:
        print(f"[r2] Decompiling (pdc) function: {func_name}")
        return self._run_r2_command(binary_path, ["aaa", f"s {func_name}", "pdc"])

    def search_strings(self, binary_path: str, keyword: str = "") -> str:
        if keyword:
            print(f"[r2] Searching strings for keyword: {keyword}")
            return self._run_r2_command(binary_path, [f"/ {keyword}"])
        else:
            print("[r2] Listing all strings")
            return self._run_r2_command(binary_path, ["izz", "izzq"])

    def get_imports(self, binary_path: str) -> str:
        print("[r2] Getting imported functions")
        return self._run_r2_command(binary_path, ["it"])

    def get_xrefs_to(self, binary_path: str, address: str) -> str:
        print(f"[r2] Getting xrefs to address: {address}")
        return self._run_r2_command(binary_path, [f"axt @ {address}"])


# ==================== Ghidra 工具 ====================
class GhidraTool:
    """
    Ghidra 工具封装 — 使用 analyzeHeadless + Java (.java) 脚本方案。
    """

    def __init__(self):
        self._check_ghidra()
        self._write_scripts()
        print("[*] Ghidra tool initialized (analyzeHeadless + 4 Java scripts).")

    def _check_ghidra(self):
        if not os.path.isfile(GHIDRA_HEADLESS):
            raise RuntimeError(f"analyzeHeadless not found: {GHIDRA_HEADLESS}")
        if not os.access(GHIDRA_HEADLESS, os.X_OK):
            raise RuntimeError(f"analyzeHeadless not executable: {GHIDRA_HEADLESS}")
        print(f"[ghidra] analyzeHeadless: {GHIDRA_HEADLESS}")

    def _write_scripts(self):
        """一次性写入四个 Java 分析脚本到 GHIDRA_SCRIPTS_DIR。"""
        os.makedirs(GHIDRA_SCRIPTS_DIR, exist_ok=True)

        # ---- 反编译脚本 ----
        decompile_java = r"""
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
                // List available functions to help debug
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
"""

        # ---- 调用关系脚本 ----
        calls_java = r"""
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
"""

        # ---- 交叉引用脚本 ----
        xrefs_java = r"""
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
"""

        # ---- 漏洞模式扫描脚本 ----
        vuln_scan_java = r"""
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
"""

        scripts = {
            "DecompileFunc.java": decompile_java,
            "FuncCalls.java": calls_java,
            "FuncXrefs.java": xrefs_java,
            "VulnScan.java": vuln_scan_java,
        }

        for name, content in scripts.items():
            path = os.path.join(GHIDRA_SCRIPTS_DIR, name)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content.strip() + "\n")
            if not os.path.isfile(path):
                raise RuntimeError(f"Failed to write script: {path}")

        print(f"[ghidra] 4 Java scripts written to {GHIDRA_SCRIPTS_DIR}")

    def _prepare_binary(self, binary_path: str) -> str:
        """确保目标文件路径为纯 ASCII。"""
        abs_path = os.path.abspath(binary_path)
        try:
            abs_path.encode('ascii')
            return abs_path
        except UnicodeEncodeError:
            tmp_dir = tempfile.mkdtemp(prefix="ghidra_bin_")
            tmp_path = os.path.join(tmp_dir, os.path.basename(binary_path))
            shutil.copy2(abs_path, tmp_path)
            os.chmod(tmp_path, 0o755)
            print(f"[ghidra] Copied to ASCII path: {tmp_path}")
            return tmp_path

    def _run_script(self, binary_path: str, script_name: str, *script_args) -> str:
        """
        通过 analyzeHeadless -postScript 执行 Java 脚本。
        返回脚本 stdout 中的有用输出，失败时返回诊断信息。
        """
        safe_binary = self._prepare_binary(binary_path)
        proj_dir = tempfile.mkdtemp(prefix="ghidra_proj_")

        cmd = [
            GHIDRA_HEADLESS,
            proj_dir,
            "analysis_project",
            "-import", safe_binary,
            "-postScript", script_name,
        ]
        cmd.extend(script_args)
        cmd.extend(["-scriptPath", GHIDRA_SCRIPTS_DIR])
        cmd.append("-deleteProject")

        print(f"[ghidra] Running: {script_name} {' '.join(script_args)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                env={**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA_HOME},
            )

            stdout = result.stdout or ""
            stderr = result.stderr or ""

            # ---- 第一步：提取脚本 println 输出 ----
            useful_lines = []
            for line in stdout.split('\n'):
                if '.java>' in line:
                    idx = line.index('>')
                    content = line[idx + 1:].strip()
                    if content.endswith('(GhidraScript)'):
                        content = content[:-len('(GhidraScript)')].strip()
                    if content:
                        useful_lines.append(content)

            output = '\n'.join(useful_lines)
            if output:
                return output

            # ---- 第二步：无脚本输出，收集诊断信息 ----
            diagnostic = []

            # 检查 stdout 中的错误/警告行
            error_keywords = [
                'ERROR', 'error', 'SCRIPT', 'script', 'compile', 'Compile',
                'Exception', 'exception', 'failed', 'Failed', 'not found',
                'WARNING', 'SEVERE'
            ]
            for line in stdout.split('\n'):
                s = line.strip()
                if not s:
                    continue
                if any(kw in s for kw in error_keywords):
                    diagnostic.append(s)

            # 检查 stderr
            if stderr.strip():
                for line in stderr.strip().split('\n'):
                    s = line.strip()
                    if s and s not in diagnostic:
                        diagnostic.append(f"[stderr] {s}")

            if diagnostic:
                # 去重并限制行数
                seen = set()
                unique = []
                for d in diagnostic:
                    if d not in seen:
                        seen.add(d)
                        unique.append(d)
                return "Script produced no output. Ghidra diagnostic:\n" + "\n".join(unique[:30])

            return (
                "No script output captured. "
                "Ghidra headless completed (rc={}) but script produced no recognizable output. "
                "Stderr: {}"
            ).format(
                result.returncode,
                stderr.strip()[:200] if stderr.strip() else "(empty)"
            )

        except subprocess.TimeoutExpired:
            return "Error: Ghidra timed out (180s)"
        except Exception as e:
            return f"Error: {str(e)}"
        finally:
            shutil.rmtree(proj_dir, ignore_errors=True)

    def decompile_function(self, binary_path: str, function_name: str) -> str:
        """反编译指定函数，返回伪 C 代码。"""
        print(f"[ghidra] Decompiling function: {function_name}")
        result = self._run_script(binary_path, "DecompileFunc.java", function_name)

        if "DECOMPILED_CODE_START" in result and "DECOMPILED_CODE_END" in result:
            start = result.index("DECOMPILED_CODE_START") + len("DECOMPILED_CODE_START")
            end = result.index("DECOMPILED_CODE_END")
            code = result[start:end].strip()
            print(f"[ghidra] Decompilation successful, {len(code)} characters.")
            return code
        else:
            # 返回完整输出（包含错误诊断）
            print(f"[ghidra] Decompilation result: {result[:200]}...")
            return result

    def get_function_calls(self, binary_path: str, function_name: str) -> str:
        """获取函数内部调用的函数列表。"""
        print(f"[ghidra] Getting function calls for: {function_name}")
        result = self._run_script(binary_path, "FuncCalls.java", function_name)
        print(f"[ghidra] {result.strip()[:200]}")
        return result

    def get_cross_references(self, binary_path: str, function_name: str) -> str:
        """获取调用该函数的引用。"""
        print(f"[ghidra] Getting cross references to: {function_name}")
        result = self._run_script(binary_path, "FuncXrefs.java", function_name)
        print(f"[ghidra] {result.strip()[:200]}")
        return result

    def vuln_scan(self, binary_path: str) -> str:
        """运行漏洞模式扫描。"""
        print("[ghidra] Running vulnerability pattern scan...")
        result = self._run_script(binary_path, "VulnScan.java")
        print(f"[ghidra] VulnScan complete, output {len(result)} chars.")
        return result

    def cleanup(self):
        """清理脚本目录。"""
        if os.path.exists(GHIDRA_SCRIPTS_DIR):
            shutil.rmtree(GHIDRA_SCRIPTS_DIR, ignore_errors=True)


# ==================== Agent 核心实现 ====================
class ReActAgent:
    def __init__(self, llm_client: OpenAI, model_name: str, tools: List[Dict],
                 scan_context: str = ""):
        self.client = llm_client
        self.model = model_name
        self.tools = tools
        self.messages = []
        self.log_entries = []
        self.scan_context = scan_context
        print("[*] ReAct Agent initialized.")
        if scan_context:
            print(f"[*] VulnScan context loaded ({len(scan_context)} chars).")

    def _build_system_prompt(self) -> str:
        prompt = (
            "你是一个使用 ReAct 模式工作的静态分析安全专家。\n"
            "目标是通过调用提供的工具，分析二进制文件 'challenge'，最终找出安全漏洞。\n"
            "\n"
            "## 重要：Ghidra 函数命名\n"
            "该二进制文件已 strip，Ghidra 会自动将函数命名为 ENTRYADDR 格式（如 FUN_00401264）。\n"
            "调用 Ghidra 工具时必须使用 Ghidra 的函数名，不能使用 'main' 等猜测名。\n"
            "如果 VulnScan 输出中列出了函数名，请直接使用那些名字。\n"
            "\n"
            "## 可用工具\n"
            "### radare2 工具\n"
            "- r2_get_functions_info: 获取所有函数列表\n"
            "- r2_disassemble_function: 反汇编指定函数（参数: function_name）\n"
            "- r2_decompile_function: 获取伪 C 代码（参数: function_name）\n"
            "- r2_search_strings: 搜索字符串（参数: keyword，可选）\n"
            "- r2_get_imports: 获取导入函数列表\n"
            "- r2_get_xrefs_to: 获取地址的交叉引用（参数: address）\n"
            "\n"
            "### Ghidra 工具（更精确）\n"
            "- ghidra_decompile_function: 反编译函数为高质量伪代码（参数: function_name）\n"
            "- ghidra_get_function_calls: 获取函数内部调用关系（参数: function_name）\n"
            "- ghidra_get_cross_references: 获取谁调用了该函数（参数: function_name）\n"
            "- ghidra_vuln_scan: 自动扫描危险函数调用模式（无参数）\n"
            "\n"
            "## 分析方法论\n"
            "1. 先查看 VulnScan 预扫描结果（如有），识别可疑的危险函数调用点\n"
            "2. 对每个可疑点，用 Ghidra 或 radare2 反编译上下文函数，理解数据流\n"
            "3. 追踪数据流路径：不可信输入源 → 中间处理/检查 → 危险汇聚点\n"
            "4. 评估边界检查是否充分：检查的上界是否大于目标缓冲区大小\n"
            "\n"
            "## 输出 Final Answer 前的必要证据\n"
            "在输出最终结论前，你必须在 Thought 中明确列出以下四类证据：\n"
            "1. **数据源**：哪个函数/地址读入不可信数据，读入到哪个缓冲区，缓冲区大小\n"
            "2. **危险汇聚点**：哪个函数/地址执行危险操作（如 strcpy），目标缓冲区大小\n"
            "3. **不充分的检查**：存在什么边界检查，检查的阈值是多少，为什么不能防止溢出\n"
            "4. **关键指令地址**：至少给出读入操作和危险操作的指令地址\n"
            "\n"
            "只有四类证据全部具备时，才能输出确定的漏洞结论。否则输出 vuln_type 为 \"unknown\"。\n"
            "\n"
            "## Final Answer JSON 格式\n"
            "当有足够证据时，输出：\n"
            "{\n"
            "    \"vuln_type\": \"漏洞类型\",\n"
            "    \"location\": \"函数名或地址\",\n"
            "    \"cause\": \"描述不可信输入如何到达危险操作，以及检查为何不充分\"\n"
            "}\n"
            "\n"
            "## 注意\n"
            "- 每次只能调用一个工具\n"
            "- Observation 只能来自工具返回\n"
            "- 不要编造信息\n"
            "- 如果某个工具返回了 Ghidra diagnostic 信息，请阅读并理解错误原因\n"
            "- 分析完成后必须输出 Final Answer JSON\n"
        )

        if self.scan_context:
            prompt += (
                "\n## VulnScan 预扫描结果（自动分析，已包含危险调用点及上下文指令）\n"
                "以下是自动扫描发现的危险函数调用，请重点分析这些位置：\n"
                "```\n"
                f"{self.scan_context}\n"
                "```\n"
                "\n"
                "请根据以上扫描结果，优先对 [INPUT] 标记的调用点追踪数据流到 [SINK] 标记的调用点，\n"
                "检查中间的长度/边界检查是否能有效防止溢出。\n"
                "注意使用 Ghidra 的函数名（如 FUN_00401264）调用其他 Ghidra 工具。\n"
            )

        return prompt

    def _execute_tool(self, tool_name: str, args: Dict) -> str:
        global r2_tool, ghidra_tool
        if r2_tool is None:
            r2_tool = Radare2Tool()
        if ghidra_tool is None:
            ghidra_tool = GhidraTool()

        try:
            if tool_name == "r2_get_functions_info":
                return r2_tool.get_functions_info(TARGET_FILE)
            elif tool_name == "r2_disassemble_function":
                return r2_tool.disassemble_function(TARGET_FILE, args.get("function_name"))
            elif tool_name == "r2_decompile_function":
                return r2_tool.decompile_function(TARGET_FILE, args.get("function_name"))
            elif tool_name == "r2_search_strings":
                return r2_tool.search_strings(TARGET_FILE, args.get("keyword", ""))
            elif tool_name == "r2_get_imports":
                return r2_tool.get_imports(TARGET_FILE)
            elif tool_name == "r2_get_xrefs_to":
                return r2_tool.get_xrefs_to(TARGET_FILE, args.get("address"))
            elif tool_name == "ghidra_decompile_function":
                return ghidra_tool.decompile_function(TARGET_FILE, args.get("function_name"))
            elif tool_name == "ghidra_get_function_calls":
                return ghidra_tool.get_function_calls(TARGET_FILE, args.get("function_name"))
            elif tool_name == "ghidra_get_cross_references":
                return ghidra_tool.get_cross_references(TARGET_FILE, args.get("function_name"))
            elif tool_name == "ghidra_vuln_scan":
                return ghidra_tool.vuln_scan(TARGET_FILE)
            else:
                return f"Unknown tool: {tool_name}"
        except Exception as e:
            return f"Tool execution error: {str(e)}"

    def run(self, user_input: str, max_iterations: int = 12) -> str:
        self.messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": user_input}
        ]

        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            print(f"\n{'='*60}")
            print(f"Round {iteration}/{max_iterations}")
            print(f"{'='*60}")
            self.log_entries.append(f"\n{'='*60}\nRound {iteration}\n{'='*60}\n")

            try:
                print("[Agent] Calling LLM...")
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=self.messages,
                    tools=self.tools,
                    tool_choice="auto",
                    temperature=0.7,
                )
                print("[Agent] LLM responded.")
                message = response.choices[0].message

                if message.content:
                    preview = message.content[:300] + "..." if len(message.content) > 300 else message.content
                    print(f"[Thought] {preview}")
                    self.log_entries.append(f"Thought: {message.content}\n")
                else:
                    print("[Thought] (No content, waiting for tool calls)")
                    self.log_entries.append("(No content, waiting for tool calls)\n")

                if message.tool_calls:
                    print(f"[Agent] LLM requested {len(message.tool_calls)} tool call(s)")
                    for tool_call in message.tool_calls:
                        tool_name = tool_call.function.name
                        tool_args = json.loads(tool_call.function.arguments)
                        print(f"[Action] {tool_name}({json.dumps(tool_args)})")
                        self.log_entries.append(f"Action: {tool_name}({json.dumps(tool_args)})\n")

                        observation = self._execute_tool(tool_name, tool_args)
                        obs_preview = observation[:500] + "..." if len(observation) > 500 else observation
                        print(f"[Observation] {obs_preview}")
                        self.log_entries.append(f"Observation: {observation}\n")

                        self.messages.append(message)
                        self.messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": observation
                        })
                else:
                    print("[Agent] No tool calls in response.")
                    content = message.content or ""
                    if "vuln_type" in content and "location" in content:
                        print("[Agent] Detected potential Final Answer JSON")
                        json_match = re.search(r'\{[^{}]*"vuln_type"[^{}]*\}', content, re.DOTALL)
                        if json_match:
                            return json_match.group()
                    if message.content:
                        self.messages.append(message)
                    else:
                        break
            except Exception as e:
                error_msg = f"LLM error: {str(e)}"
                print(f"[Error] {error_msg}")
                self.log_entries.append(error_msg)
                return json.dumps({
                    "vuln_type": "analysis_error",
                    "location": "unknown",
                    "cause": error_msg
                })

        print("[Agent] Max iterations reached without Final Answer.")
        return json.dumps({
            "vuln_type": "not_found",
            "location": "unknown",
            "cause": "Maximum iterations reached"
        })

    def save_log(self, log_path: str):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"ReAct Agent Analysis Log\n")
            f.write(f"Started at: {datetime.now().isoformat()}\n")
            f.write(f"Target: {TARGET_FILE}\n")
            f.write(f"Model: {MODEL_NAME}\n")
            f.write(f"\n{'-'*80}\n\n")
            if self.scan_context:
                f.write("=== VulnScan Pre-scan Context ===\n")
                f.write(self.scan_context)
                f.write(f"\n{'-'*80}\n\n")
            f.writelines(self.log_entries)
        print(f"[Log] Saved to {log_path}")


# ==================== 定义 LLM 工具 Schema ====================
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "r2_get_functions_info",
            "description": "获取所有函数列表",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "r2_disassemble_function",
            "description": "反汇编指定函数",
            "parameters": {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "r2_decompile_function",
            "description": "使用 radare2 获取伪 C 代码",
            "parameters": {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "r2_search_strings",
            "description": "搜索字符串",
            "parameters": {
                "type": "object",
                "properties": {"keyword": {"type": "string"}},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "r2_get_imports",
            "description": "获取导入函数",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "r2_get_xrefs_to",
            "description": "获取地址的交叉引用",
            "parameters": {
                "type": "object",
                "properties": {"address": {"type": "string"}},
                "required": ["address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra_decompile_function",
            "description": "使用 Ghidra 反编译函数，返回高质量伪代码",
            "parameters": {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra_get_function_calls",
            "description": "获取函数内部调用的函数列表",
            "parameters": {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra_get_cross_references",
            "description": "获取调用该函数的引用",
            "parameters": {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra_vuln_scan",
            "description": (
                "自动扫描二进制文件中所有危险函数调用（如 fgets/strcpy/system 等），"
                "输出每个调用点的函数名、地址及前后上下文指令。"
                "用于快速定位潜在漏洞位置。"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    }
]

# ==================== 全局工具实例 ====================
r2_tool = None
ghidra_tool = None


# ==================== 主函数 ====================
def main():
    global r2_tool, ghidra_tool  # <-- 修复：声明为全局变量

    if not os.path.exists(TARGET_FILE):
        print(f"Error: Target file not found at {TARGET_FILE}")
        sys.exit(1)

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    print(f"Starting ReAct Agent analysis...")
    print(f"Target: {TARGET_FILE}")
    print(f"Model: {MODEL_NAME}")

    # ==================== 第一阶段：VulnScan 预扫描 ====================
    print(f"\n{'='*60}")
    print("Phase 1: Pre-scan with VulnScan")
    print(f"{'='*60}")

    scan_context = ""
    try:
        if ghidra_tool is None:
            ghidra_tool = GhidraTool()
        scan_context = ghidra_tool.vuln_scan(TARGET_FILE)
        if scan_context and not scan_context.startswith("Error") and not scan_context.startswith("No script"):
            print(f"[Pre-scan] VulnScan completed successfully ({len(scan_context)} chars).")
            print(f"[Pre-scan] Scan results will be injected into LLM context.")
        else:
            print(f"[Pre-scan] VulnScan returned no useful results, proceeding without context.")
            if scan_context:
                print(f"[Pre-scan] Raw output: {scan_context[:300]}")
            scan_context = ""
    except Exception as e:
        print(f"[Pre-scan] VulnScan failed: {e}")
        print(f"[Pre-scan] Proceeding without scan context.")
        scan_context = ""

    # ==================== 第二阶段：LLM 驱动的深度分析 ====================
    print(f"\n{'='*60}")
    print("Phase 2: LLM-driven ReAct Analysis")
    print(f"{'='*60}")

    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    agent = ReActAgent(client, MODEL_NAME, TOOLS, scan_context=scan_context)

    user_prompt = "请分析目标二进制文件，找出其中的安全漏洞。"
    if scan_context:
        user_prompt += (
            "\n\nVulnScan 预扫描已经发现了可疑的危险函数调用点及上下文指令（见系统提示）。"
            "请根据扫描结果重点分析这些位置，追踪数据流并评估边界检查的充分性。"
        )

    final_answer = agent.run(user_prompt, max_iterations=12)
    agent.save_log(LOG_FILE)

    # 清理 Ghidra 脚本
    if ghidra_tool is not None:
        ghidra_tool.cleanup()

    # ==================== 保存结果 ====================
    try:
        result = json.loads(final_answer)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n[Result] Saved to {OUTPUT_FILE}")
        print("[Final Answer]")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except json.JSONDecodeError:
        match = re.search(r'\{[^{}]*\}', final_answer)
        if match:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(match.group())
            print(f"\n[Result] Extracted JSON saved to {OUTPUT_FILE}")
        else:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(final_answer)
            print(f"\n[Result] Raw output saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

