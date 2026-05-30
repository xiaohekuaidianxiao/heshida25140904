"""
tools.py — angr 工具封装
包含两个原子工具：
  1. controlled_explore: 受控路径探索
  2. solve_input: 从目标状态求解输入
"""

import angr
import json

# ============================================================
# 工具 1：受控探索
# ============================================================
def controlled_explore(binary_path, find_addrs, avoid_addrs, max_steps=100):
    """
    在指定的 find/avoid 约束下，驱动 SimulationManager 探索路径。

    参数：
        binary_path  : str        - 可执行文件路径
        find_addrs   : list[int]  - 目标地址列表（如 Success 输出的基本块地址）
        avoid_addrs  : list[int]  - 需避开的地址列表（如死循环相关地址）
        max_steps    : int        - explore 的最大步数上限

    返回：
        dict - 结构化观察结果
    """
    proj = angr.Project(binary_path, auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    # 使用 find/avoid 进行有约束的探索
    simgr.explore(find=find_addrs, avoid=avoid_addrs, n=max_steps)

    # 汇总状态
    result = {
        "tool": "controlled_explore",
        "found": len(simgr.found),
        "active": len(simgr.active),
        "avoided": len(simgr.avoided),
        "deadended": len(simgr.deadended),
        "errored": len(simgr.errored),
        "reached_target": len(simgr.found) > 0,
    }

    # 如果找到了目标状态，缓存起来供 solve_input 使用
    if simgr.found:
        # 保存 found 状态的关键约束信息摘要
        found_state = simgr.found[0]
        try:
            input_data = found_state.posix.dumps(0)
            result["symbolic_input_size"] = len(input_data)
        except Exception:
            result["symbolic_input_size"] = "unknown"

    return result


# ============================================================
# 工具 2：输入求解
# ============================================================
def solve_input(binary_path, find_addrs, avoid_addrs, max_steps=100):
    """
    先探索到目标状态，然后从符号约束中求解具体输入。

    参数：
        binary_path  : str        - 可执行文件路径
        find_addrs   : list[int]  - 目标地址列表
        avoid_addrs  : list[int]  - 需避开的地址列表
        max_steps    : int        - explore 的最大步数上限

    返回：
        dict - 包含求解结果的字典
    """
    proj = angr.Project(binary_path, auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    simgr.explore(find=find_addrs, avoid=avoid_addrs, n=max_steps)

    if not simgr.found:
        return {
            "tool": "solve_input",
            "success": False,
            "message": "未找到到达目标的路径"
        }

    found_state = simgr.found[0]

    # 从 stdin (fd=0) 中求解具体输入
    try:
        input_bytes = found_state.posix.dumps(0)
        concrete_input = found_state.solver.eval(input_bytes, cast_to=bytes)

        # 过滤掉 null 终止符等，提取可打印部分
        printable = concrete_input.split(b'\x00')[0]

        return {
            "tool": "solve_input",
            "success": True,
            "input_ascii": printable.decode('ascii', errors='replace'),
            "input_hex": printable.hex(),
            "raw_hex": concrete_input.hex(),
            "found_states_count": len(simgr.found)
        }
    except Exception as e:
        return {
            "tool": "solve_input",
            "success": False,
            "message": f"求解失败: {str(e)}"
        }


# ============================================================
# 工具注册表（供主循环派发使用）
# ============================================================
TOOLS = {
    "controlled_explore": controlled_explore,
    "solve_input": solve_input,
}

def call_tool(tool_name, binary_path, find_addrs, avoid_addrs, **kwargs):
    """统一的工具调用入口"""
    if tool_name not in TOOLS:
        return {"error": f"未知工具: {tool_name}"}
    return TOOLS[tool_name](binary_path, find_addrs, avoid_addrs, **kwargs)
