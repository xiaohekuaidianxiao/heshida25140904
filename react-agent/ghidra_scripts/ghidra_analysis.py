# ghidra_scripts/ghidra_analysis.py
"""
独立 Ghidra 分析脚本。
可直接通过 pyghidra 运行，也可作为 agent.py 中 GhidraTool 的后备参考。
使用 pyghidra.open_program() 上下文管理器，确保正确初始化和资源清理。
"""

import sys
import pyghidra


def decompile_function(binary_path: str, function_name: str) -> str:
    """反编译指定函数，返回伪 C 代码。"""
    with pyghidra.open_program(binary_path) as flat_api:
        program = flat_api.getCurrentProgram()
        if program is None:
            return f"Failed to open binary: {binary_path}"

        listing = program.getListing()
        func = listing.getFunction(function_name)

        # 若按名称找不到，尝试符号表查找
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
        from ghidra.util.task import ConsoleTaskMonitor

        decompiler = DecompInterface()
        decompiler.openProgram(program)
        monitor = ConsoleTaskMonitor()
        decompiled = decompiler.decompileFunction(func, 60, monitor)

        if decompiled is None or not decompiled.decompileCompleted():
            error_msg = decompiled.getErrorMessage() if decompiled else "Unknown error"
            return f"Decompilation failed for function '{function_name}': {error_msg}"

        return decompiled.getDecompiledFunction().getC()


def get_function_calls(binary_path: str, function_name: str) -> str:
    """获取函数内部调用的其他函数列表。"""
    with pyghidra.open_program(binary_path) as flat_api:
        program = flat_api.getCurrentProgram()
        if program is None:
            return f"Failed to open binary: {binary_path}"

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

        return f"Called functions: {', '.join(set(calls))}" if calls else "No calls found."


def get_cross_references(binary_path: str, function_name: str) -> str:
    """获取调用该函数的其他函数。"""
    with pyghidra.open_program(binary_path) as flat_api:
        program = flat_api.getCurrentProgram()
        if program is None:
            return f"Failed to open binary: {binary_path}"

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

        return f"Called by: {', '.join(set(refs))}" if refs else "No cross references found."


if __name__ == "__main__":
    # 用法示例: python ghidra_analysis.py <binary_path> <function_name>
    if len(sys.argv) < 3:
        print("Usage: python ghidra_analysis.py <binary_path> <function_name>")
        sys.exit(1)
    binary = sys.argv[1]
    func_name = sys.argv[2]
    print(decompile_function(binary, func_name))

