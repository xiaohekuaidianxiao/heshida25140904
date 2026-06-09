#!/usr/bin/env python3
"""
ReAct Agent for Static Binary Analysis
With detailed console printing for debugging and monitoring.
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
# LLM 配置
API_KEY = "sk-cwoz7cy5e7vrtclemqp8qephx47tb5a83d6ktf7uzseh7zcr"
BASE_URL = "https://api.xiaomimimo.com/v1"
MODEL_NAME = "xiaomi/mimo-v2.5-pro"

# 路径配置
GHIDRA_HEADLESS = "/usr/share/ghidra/support/analyzeHeadless"  # 保留备用
TARGET_FILE = "./targets/challenge"
LOG_FILE = "./logs/run.txt"
OUTPUT_FILE = "./output/vuln.json"

# ==================== 初始化 pyghidra ====================
if "GHIDRA_INSTALL_DIR" not in os.environ:
    os.environ["GHIDRA_INSTALL_DIR"] = "/usr/share/ghidra"

import pyghidra

# ==================== 工具封装 ====================
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
        commands = ["aaa", "afl"]
        return self._run_r2_command(binary_path, commands)
    
    def disassemble_function(self, binary_path: str, func_name: str) -> str:
        print(f"[r2] Disassembling function: {func_name}")
        commands = ["aaa", f"s {func_name}", "pdf"]
        return self._run_r2_command(binary_path, commands)
    
    def decompile_function(self, binary_path: str, func_name: str) -> str:
        print(f"[r2] Decompiling (pdc) function: {func_name}")
        commands = ["aaa", f"s {func_name}", "pdc"]
        return self._run_r2_command(binary_path, commands)
    
    def search_strings(self, binary_path: str, keyword: str = "") -> str:
        if keyword:
            print(f"[r2] Searching strings for keyword: {keyword}")
            commands = [f"/ {keyword}"]
        else:
            print("[r2] Listing all strings")
            commands = ["izz", "izzq"]
        return self._run_r2_command(binary_path, commands)
    
    def get_imports(self, binary_path: str) -> str:
        print("[r2] Getting imported functions")
        commands = ["it"]
        return self._run_r2_command(binary_path, commands)
    
    def get_xrefs_to(self, binary_path: str, address: str) -> str:
        print(f"[r2] Getting xrefs to address: {address}")
        commands = [f"axt @ {address}"]
        return self._run_r2_command(binary_path, commands)

class GhidraTool:
    """Ghidra 工具封装，使用 pyghidra 直接调用"""
    
    def __init__(self):
        self.initialized = False
        self.flat_api = None
        self.current_program = None
        self.current_binary = None
        self.temp_dir = None
        print("[*] Ghidra tool initialized (pyghidra).")
    
    def _ensure_initialized(self, binary_path: str):
        if self.initialized and self.current_binary == binary_path:
            return
        print(f"[ghidra] Initializing Ghidra with binary: {binary_path}")
        if self.current_program:
            self.current_program.close()
        pyghidra.start()
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.app.util.headless import HeadlessAnalyzer
        
        self.temp_dir = tempfile.mkdtemp()
        project_name = "temp_project"
        analyzer = HeadlessAnalyzer(self.temp_dir, project_name, True)
        self.current_program = analyzer.importProgram(binary_path)
        if self.current_program is None:
            raise Exception(f"Failed to import binary: {binary_path}")
        self.flat_api = FlatProgramAPI(self.current_program)
        self.current_binary = binary_path
        self.initialized = True
        print("[ghidra] Initialization complete.")
    
    def decompile_function(self, binary_path: str, function_name: str) -> str:
        print(f"[ghidra] Decompiling function: {function_name}")
        try:
            self._ensure_initialized(binary_path)
            program = self.current_program
            listing = program.getListing()
            func = listing.getFunction(function_name)
            if func is None:
                symbol_table = program.getSymbolTable()
                symbols = symbol_table.getSymbols(function_name)
                for sym in symbols:
                    if sym.isFunction():
                        func = listing.getFunctionAt(sym.getAddress())
                        break
            if func is None:
                return f"Function '{function_name}' not found."
            
            from ghidra.app.decompiler import DecompInterface
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            from ghidra.util.task import ConsoleTaskMonitor
            monitor = ConsoleTaskMonitor()
            decompiled = decompiler.decompileFunction(func, 0, monitor)
            if decompiled is None or not decompiled.decompileCompleted():
                return f"Decompilation failed for function '{function_name}'."
            code = decompiled.getDecompiledFunction().getC()
            print(f"[ghidra] Decompilation successful, got {len(code)} characters.")
            return code
        except Exception as e:
            return f"Ghidra error: {str(e)}"
    
    def get_function_calls(self, binary_path: str, function_name: str) -> str:
        print(f"[ghidra] Getting function calls for: {function_name}")
        try:
            self._ensure_initialized(binary_path)
            program = self.current_program
            listing = program.getListing()
            func = listing.getFunction(function_name)
            if func is None:
                return f"Function '{function_name}' not found."
            calls = []
            instructions = listing.getInstructions(func.getBody(), True)
            for ins in instructions:
                mnemonic = ins.getMnemonicString().lower()
                if mnemonic in ["call", "callq", "jmp"]:
                    refs = ins.getReferencesFrom()
                    for ref in refs:
                        to_addr = ref.getToAddress()
                        called_func = listing.getFunctionContaining(to_addr)
                        if called_func:
                            calls.append(called_func.getName())
            result = f"Called functions: {', '.join(set(calls))}" if calls else "No calls found."
            print(f"[ghidra] {result}")
            return result
        except Exception as e:
            return f"Ghidra error: {str(e)}"
    
    def get_cross_references(self, binary_path: str, function_name: str) -> str:
        print(f"[ghidra] Getting cross references to: {function_name}")
        try:
            self._ensure_initialized(binary_path)
            program = self.current_program
            listing = program.getListing()
            func = listing.getFunction(function_name)
            if func is None:
                return f"Function '{function_name}' not found."
            refs = []
            ref_manager = program.getReferenceManager()
            references = ref_manager.getReferencesTo(func.getEntryPoint())
            for ref in references:
                from_addr = ref.getFromAddress()
                caller = listing.getFunctionContaining(from_addr)
                if caller:
                    refs.append(caller.getName())
            result = f"Called by: {', '.join(set(refs))}" if refs else "No cross references found."
            print(f"[ghidra] {result}")
            return result
        except Exception as e:
            return f"Ghidra error: {str(e)}"
    
    def __del__(self):
        if hasattr(self, 'current_program') and self.current_program:
            try:
                self.current_program.close()
            except:
                pass
        if hasattr(self, 'temp_dir') and self.temp_dir:
            shutil.rmtree(self.temp_dir, ignore_errors=True)

# ==================== Agent 核心实现 ====================
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
                func = args.get("function_name")
                return r2_tool.disassemble_function(TARGET_FILE, func)
            elif tool_name == "r2_decompile_function":
                func = args.get("function_name")
                return r2_tool.decompile_function(TARGET_FILE, func)
            elif tool_name == "r2_search_strings":
                keyword = args.get("keyword", "")
                return r2_tool.search_strings(TARGET_FILE, keyword)
            elif tool_name == "r2_get_imports":
                return r2_tool.get_imports(TARGET_FILE)
            elif tool_name == "r2_get_xrefs_to":
                addr = args.get("address")
                return r2_tool.get_xrefs_to(TARGET_FILE, addr)
            elif tool_name == "ghidra_decompile_function":
                func = args.get("function_name")
                return ghidra_tool.decompile_function(TARGET_FILE, func)
            elif tool_name == "ghidra_get_function_calls":
                func = args.get("function_name")
                return ghidra_tool.get_function_calls(TARGET_FILE, func)
            elif tool_name == "ghidra_get_cross_references":
                func = args.get("function_name")
                return ghidra_tool.get_cross_references(TARGET_FILE, func)
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
                
                # 打印 Thought
                if message.content:
                    print(f"[Thought] {message.content[:200]}..." if len(message.content) > 200 else f"[Thought] {message.content}")
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
                        # 截断过长的 observation 打印
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
    }
]

# ==================== 全局工具实例 ====================
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
    print(f"Base URL: {BASE_URL}")
    
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    agent = ReActAgent(client, MODEL_NAME, TOOLS)
    
    final_answer = agent.run("请分析目标二进制文件，找出其中的安全漏洞。", max_iterations=12)
    agent.save_log(LOG_FILE)
    
    # 保存结果
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
