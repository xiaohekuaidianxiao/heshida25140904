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
API_KEY = "sk-cwoz7cy5e7vrtclemqp8qephx47tb5a83d6ktf7uzseh7zcr"
BASE_URL = "https://api.xiaomimimo.com/v1"
MODEL_NAME = "xiaomi/mimo-v2.5-pro"

GHIDRA_HOME = "/usr/share/ghidra"
GHIDRA_HEADLESS = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")

TARGET_FILE = "./targets/challenge"
LOG_FILE = "./logs/run.txt"
OUTPUT_FILE = "./output/vuln.json"

# Ghidra Python 脚本存放目录（永久路径，只写一次）
GHIDRA_SCRIPTS_DIR = "/tmp/ghidra_agent_scripts"


# ==================== Radare2 工具（无变化） ====================
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


# ==================== Ghidra 工具（重写版） ====================
class GhidraTool:
    """
    Ghidra 工具封装 — 使用 subprocess 隔离方案。
    
    每次工具调用都在独立子进程中完成（纯 ASCII 环境），
    彻底避免 pyghidra 在主进程中因 sys.path 含非 ASCII 字符而崩溃。
    """

    def __init__(self):
        self._check_ghidra()
        self._check_python()
        print("[*] Ghidra tool initialized (subprocess isolation).")

    def _check_ghidra(self):
        if not os.path.isfile(GHIDRA_HEADLESS):
            raise RuntimeError(f"analyzeHeadless not found at {GHIDRA_HEADLESS}")
        print(f"[ghidra] analyzeHeadless: {GHIDRA_HEADLESS}")

    def _check_python(self):
        """确认当前 Python 可执行文件路径是纯 ASCII。"""
        try:
            sys.executable.encode('ascii')
            print(f"[ghidra] Python: {sys.executable}")
        except UnicodeEncodeError:
            raise RuntimeError(
                f"Python executable path contains non-ASCII: {sys.executable}\n"
                f"Please use a Python from a pure ASCII path."
            )

    def _prepare_binary(self, binary_path: str) -> str:
        """将二进制文件复制到 /tmp 下的纯 ASCII 路径。"""
        abs_path = os.path.abspath(binary_path)
        try:
            abs_path.encode('ascii')
            return abs_path
        except UnicodeEncodeError:
            pass
        tmp_dir = tempfile.mkdtemp(prefix="ghidra_bin_")
        tmp_path = os.path.join(tmp_dir, os.path.basename(binary_path))
        shutil.copy2(abs_path, tmp_path)
        os.chmod(tmp_path, 0o755)
        print(f"[ghidra] Copied to ASCII-safe path: {tmp_path}")
        return tmp_path

    def _run_in_subprocess(self, binary_path: str, command: str, func_name: str = "") -> str:
        """
        在干净子进程中执行 Ghidra 分析。
        子进程使用纯 ASCII 环境，彻底隔离 sys.path 污染。
        """
        safe_binary = self._prepare_binary(binary_path)

        # ---- 构建子进程脚本 ----
        worker_script = r'''
import os, sys, tempfile, shutil

# ===== 1. 强制干净环境 =====
os.environ["GHIDRA_INSTALL_DIR"] = "/usr/share/ghidra"
os.chdir("/tmp")

# ===== 2. 清理 sys.path 中所有非 ASCII 路径 =====
clean = []
for p in sys.path:
    try:
        p.encode('ascii')
        clean.append(p)
    except UnicodeEncodeError:
        pass
sys.path = clean

# ===== 3. 启动 pyghidra =====
import pyghidra
pyghidra.start()

from ghidra.framework.project import DefaultProjectManager
from ghidra.app.util.importer import AutoImporter
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor
from java.io import File as JavaFile
from ghidra.app.decompiler import DecompInterface

binary_path = sys.argv[1]
command     = sys.argv[2]
func_name   = sys.argv[3] if len(sys.argv) > 3 else ""

temp_dir = tempfile.mkdtemp(prefix="ghidra_work_")
try:
    # 创建项目、导入、分析
    project_mgr = DefaultProjectManager()
    project = project_mgr.createProject(temp_dir, "proj", True)
    domain_folder = project.getRootFolder()

    java_file = JavaFile(binary_path)
    monitor = ConsoleTaskMonitor()
    domain_file = AutoImporter.importByUsingBestGuess(java_file, domain_folder, None, monitor)
    if domain_file is None:
        print("ERROR: AutoImporter failed")
        sys.exit(1)

    program = domain_file.getDomainObject("analysis", True, False, monitor)
    flat_api = FlatProgramAPI(program)
    flat_api.analyzeAll(program)

    listing = program.getListing()

    # 查找函数
    func = listing.getFunction(func_name)
    if func is None:
        sym_table = program.getSymbolTable()
        for sym in sym_table.getSymbols(func_name):
            if sym.isFunction():
                func = listing.getFunctionAt(sym.getAddress())
                if func is not None:
                    break

    if func is None:
        print("ERROR: Function '" + func_name + "' not found.")
    elif command == "decompile":
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        results = decompiler.decompileFunction(func, 60, monitor)
        if results is not None and results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            print("DECOMPILED_CODE_START")
            print(code)
            print("DECOMPILED_CODE_END")
        else:
            err = results.getErrorMessage() if results is not None else "unknown"
            print("ERROR: Decompilation failed: " + err)
        decompiler.dispose()
    elif command == "calls":
        calls = set()
        for ins in listing.getInstructions(func.getBody(), True):
            m = ins.getMnemonicString().lower()
            if m in ("call", "callq", "jmp"):
                for ref in ins.getReferencesFrom():
                    cf = listing.getFunctionContaining(ref.getToAddress())
                    if cf:
                        calls.add(cf.getName())
        if calls:
            print("Called functions: " + ", ".join(sorted(calls)))
        else:
            print("No calls found.")
    elif command == "xrefs":
        callers = set()
        for ref in program.getReferenceManager().getReferencesTo(func.getEntryPoint()):
            c = listing.getFunctionContaining(ref.getFromAddress())
            if c:
                callers.add(c.getName())
        if callers:
            print("Called by: " + ", ".join(sorted(callers)))
        else:
            print("No cross references found.")

    program.release(None)
    project.close()
finally:
    shutil.rmtree(temp_dir, ignore_errors=True)
'''

        # 写入 /tmp
        script_path = '/tmp/_ghidra_worker.py'
        with open(script_path, 'w', encoding='ascii') as f:
            f.write(worker_script)

        # ---- 构建纯 ASCII 环境变量 ----
        clean_env = {
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': os.environ.get('HOME', '/root'),
            'GHIDRA_INSTALL_DIR': '/usr/share/ghidra',
            'LANG': 'C.UTF-8',
            'LC_ALL': 'C.UTF-8',
        }

        # 确保 HOME 是 ASCII
        try:
            clean_env['HOME'].encode('ascii')
        except UnicodeEncodeError:
            clean_env['HOME'] = '/root'

        # 如果 PYTHONPATH 有必要，只添加纯 ASCII 路径
        # （通常不需要，Python 会自动找到标准库和 site-packages）
        venv_base = os.path.dirname(os.path.dirname(sys.executable))
        venv_lib = os.path.join(
            venv_base, 'lib',
            f'python{sys.version_info.major}.{sys.version_info.minor}',
            'site-packages'
        )
        try:
            venv_lib.encode('ascii')
            clean_env['PYTHONPATH'] = venv_lib
        except UnicodeEncodeError:
            # 如果 venv 路径含非 ASCII，不设置 PYTHONPATH
            # 子进程会用系统 Python（需要确认 pyghidra 在系统 Python 中也可用）
            pass

        print(f"[ghidra] Running: {command}({func_name})")

        try:
            result = subprocess.run(
                [sys.executable, script_path, safe_binary, command, func_name],
                capture_output=True,
                text=True,
                timeout=300,
                cwd='/tmp',
                env=clean_env,
            )

            # 清理脚本
            try:
                os.remove(script_path)
            except OSError:
                pass

            stdout = result.stdout
            stderr = result.stderr

            if result.returncode != 0:
                stderr_tail = stderr[-800:] if stderr else "no stderr"
                print(f"[ghidra] STDERR:\n{stderr_tail}")
                return f"Ghidra error (rc={result.returncode}): {stderr_tail[-500:]}"

            return stdout if stdout.strip() else "No output from Ghidra."

        except subprocess.TimeoutExpired:
            try:
                os.remove(script_path)
            except OSError:
                pass
            return "Error: Ghidra subprocess timed out (300s)"
        except Exception as e:
            try:
                os.remove(script_path)
            except OSError:
                pass
            return f"Error: {str(e)}"

    def decompile_function(self, binary_path: str, function_name: str) -> str:
        """反编译指定函数，返回伪 C 代码。"""
        print(f"[ghidra] Decompiling function: {function_name}")
        result = self._run_in_subprocess(binary_path, "decompile", function_name)

        if "DECOMPILED_CODE_START" in result and "DECOMPILED_CODE_END" in result:
            start = result.index("DECOMPILED_CODE_START") + len("DECOMPILED_CODE_START")
            end = result.index("DECOMPILED_CODE_END")
            code = result[start:end].strip()
            print(f"[ghidra] Decompilation successful, got {len(code)} characters.")
            return code
        elif "ERROR:" in result:
            return result
        else:
            return f"Ghidra output:\n{result}"

    def get_function_calls(self, binary_path: str, function_name: str) -> str:
        """获取函数内部调用的函数列表。"""
        print(f"[ghidra] Getting function calls for: {function_name}")
        result = self._run_in_subprocess(binary_path, "calls", function_name)
        print(f"[ghidra] {result.strip()}")
        return result

    def get_cross_references(self, binary_path: str, function_name: str) -> str:
        """获取调用该函数的引用。"""
        print(f"[ghidra] Getting cross references to: {function_name}")
        result = self._run_in_subprocess(binary_path, "xrefs", function_name)
        print(f"[ghidra] {result.strip()}")
        return result

    def cleanup(self):
        """清理（subprocess 方案无需额外清理）。"""
        pass

    def __del__(self):
        pass

# ==================== Agent 核心实现（无变化） ====================
class ReActAgent:
    def __init__(self, llm_client: OpenAI, model_name: str, tools: List[Dict]):
        self.client = llm_client
        self.model = model_name
        self.tools = tools
        self.messages = []
        self.log_entries = []
        print("[*] ReAct Agent initialized.")

    def _build_system_prompt(self) -> str:
        return """你是一个使用 ReAct 模式工作的静态分析安全专家。目标是通过调用提供的工具，分析二进制文件 'challenge'，最终找出安全漏洞。

## 可用工具
### radare2 工具
- r2_get_functions_info: 获取所有函数列表
- r2_disassemble_function: 反汇编指定函数（参数: function_name）
- r2_decompile_function: 获取伪 C 代码（参数: function_name）
- r2_search_strings: 搜索字符串（参数: keyword，可选）
- r2_get_imports: 获取导入函数列表
- r2_get_xrefs_to: 获取地址的交叉引用（参数: address）

### Ghidra 工具（更精确）
- ghidra_decompile_function: 反编译函数为高质量伪代码（参数: function_name）
- ghidra_get_function_calls: 获取函数内部调用关系（参数: function_name）
- ghidra_get_cross_references: 获取谁调用了该函数（参数: function_name）

## 分析指导
1. 先用 radare2 获取基本信息（函数、导入、字符串）
2. 关注危险函数: gets, strcpy, sprintf, system, malloc/free 配对等
3. 使用 Ghidra 反编译可疑函数，分析数据流
4. 当有足够证据时，输出 Final Answer JSON，格式：
{
    "vuln_type": "漏洞类型（如 stack_buffer_overflow, use_after_free, format_string 等）",
    "location": "函数名或地址",
    "cause": "不可信输入如何到达危险操作的一两句话"
}
如果没有发现漏洞，输出 vuln_type 为 "none"。

## 注意
- 每次只能调用一个工具
- Observation 只能来自工具返回
- 不要编造信息
- 分析完成后必须输出 Final Answer JSON
"""

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
                    preview = message.content[:200] + "..." if len(message.content) > 200 else message.content
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
                return json.dumps({"vuln_type": "analysis_error", "location": "unknown", "cause": error_msg})

        print("[Agent] Max iterations reached without Final Answer.")
        return json.dumps({"vuln_type": "not_found", "location": "unknown", "cause": "Maximum iterations reached"})

    def save_log(self, log_path: str):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"ReAct Agent Analysis Log\nStarted at: {datetime.now().isoformat()}\n")
            f.write(f"Target: {TARGET_FILE}\nModel: {MODEL_NAME}\n\n{'-'*80}\n\n")
            f.writelines(self.log_entries)
        print(f"[Log] Saved to {log_path}")


# ==================== 工具 Schema（无变化） ====================
TOOLS = [
    {"type": "function", "function": {"name": "r2_get_functions_info", "description": "获取所有函数列表", "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "r2_disassemble_function", "description": "反汇编指定函数", "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]}}},
    {"type": "function", "function": {"name": "r2_decompile_function", "description": "使用 radare2 获取伪 C 代码", "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]}}},
    {"type": "function", "function": {"name": "r2_search_strings", "description": "搜索字符串", "parameters": {"type": "object", "properties": {"keyword": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {"name": "r2_get_imports", "description": "获取导入函数", "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "r2_get_xrefs_to", "description": "获取地址的交叉引用", "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]}}},
    {"type": "function", "function": {"name": "ghidra_decompile_function", "description": "使用 Ghidra 反编译函数，返回高质量伪代码", "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]}}},
    {"type": "function", "function": {"name": "ghidra_get_function_calls", "description": "获取函数内部调用的函数列表", "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]}}},
    {"type": "function", "function": {"name": "ghidra_get_cross_references", "description": "获取调用该函数的引用", "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]}}}
]

# ==================== 全局实例 ====================
r2_tool = None
ghidra_tool = None


# ==================== 主函数 ====================
def main():
    if not os.path.exists(TARGET_FILE):
        print(f"Error: Target file not found at {TARGET_FILE}")
        sys.exit(1)

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    print(f"Starting ReAct Agent analysis...")
    print(f"Target: {TARGET_FILE}")
    print(f"Model: {MODEL_NAME}")

    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    agent = ReActAgent(client, MODEL_NAME, TOOLS)

    final_answer = agent.run("请分析目标二进制文件，找出其中的安全漏洞。", max_iterations=12)
    agent.save_log(LOG_FILE)

    if ghidra_tool:
        ghidra_tool.cleanup()

    try:
        result = json.loads(final_answer)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n[Result] Saved to {OUTPUT_FILE}")
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

