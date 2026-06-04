"""
tools.py — angr 工具封装（修复版）
两个工具：controlled_explore / solve_input
"""

import angr


def controlled_explore(binary_path, find_addrs, avoid_addrs, max_steps=100):
    """在 find/avoid 约束下探索路径，返回路径统计。"""
    proj = angr.Project(binary_path, auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    simgr.explore(find=find_addrs, avoid=avoid_addrs, n=max_steps)

    result = {
        "tool": "controlled_explore",
        "found":      len(simgr.stashes.get("found", [])),
        "active":     len(simgr.stashes.get("active", [])),
        "avoided":    len(simgr.stashes.get("avoided", [])),
        "deadended":  len(simgr.stashes.get("deadended", [])),
        "errored":    len(simgr.stashes.get("errored", [])),
        "reached_target": len(simgr.stashes.get("found", [])) > 0,
    }

    return result


def solve_input(binary_path, find_addrs, avoid_addrs, max_steps=100):
    """探索并从成功状态中求解具体输入。"""
    proj = angr.Project(binary_path, auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    simgr.explore(find=find_addrs, avoid=avoid_addrs, n=max_steps)

    if not simgr.stashes.get("found"):
        return {
            "tool": "solve_input",
            "success": False,
            "message": "未到达目标路径"
        }

    found_state = simgr.found[0]

    try:
        # ★ 关键修复：posix.dumps(0) 直接返回 concrete bytes
        #    不需要再调用 solver.eval()
        stdin_bytes = found_state.posix.dumps(0)

        # 取第一个 \x00 之前的内容（有效输入部分）
        printable = stdin_bytes.split(b'\x00')[0]

        return {
            "tool": "solve_input",
            "success": True,
            "input_ascii": printable.decode("ascii", errors="replace"),
            "input_hex": printable.hex(),
            "raw_hex": stdin_bytes.hex(),
            "found_states": len(simgr.stashes.get("found", [])),
        }

    except Exception as e:
        # 备用方案：直接从符号变量求解
        try:
            stdin_file = found_state.posix.stdin
            sym_content = stdin_file.load(0, 10)  # 读10字节的符号内容
            concrete = found_state.solver.eval(sym_content, cast_to=bytes)
            printable = concrete.split(b'\x00')[0]
            return {
                "tool": "solve_input",
                "success": True,
                "input_ascii": printable.decode("ascii", errors="replace"),
                "input_hex": printable.hex(),
                "method": "solver_eval_fallback",
            }
        except Exception as e2:
            return {
                "tool": "solve_input",
                "success": False,
                "message": f"求解失败: {e} | 备用方案也失败: {e2}"
            }
