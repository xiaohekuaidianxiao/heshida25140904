import angr
import claripy

def find_addrs(binary_path):
    """用 angr 符号执行自动发现关键地址"""
    proj = angr.Project(binary_path, auto_load_libs=False)

    # 创建初始状态，从 main 开始
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    # 先做一步 CFG 分析，打印所有基本块的反汇编
    cfg = proj.analyses.CFGFast(normalize=True)

    print("=== 所有函数 ===")
    for func in cfg.kb.functions.values():
        if func.is_plt:
            continue
        print(f"函数: {func.name} @ {hex(func.addr)}")

    print("\n=== check_password 反汇编 ===")
    check_func = None
    for func in cfg.kb.functions.values():
        if func.name == "check_password":
            check_func = func
            break

    success_call_addr = None  # 调用 printf("Success!") 之前的地址
    trap_call_addr = None     # 调用 gadget_trap 之前的地址

    if check_func:
        for block in check_func.blocks:
            capstone_block = block.capstone
            for insn in capstone_block.insns:
                print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")

    print("\n=== gadget_trap 反汇编 ===")
    trap_func = None
    for func in cfg.kb.functions.values():
        if func.name == "gadget_trap":
            trap_func = func
            break

    if trap_func:
        print(f"gadget_trap 起始地址: {hex(trap_func.addr)}")
        for block in trap_func.blocks:
            for insn in block.capstone.insns:
                print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")

    # 用 grep 模拟：在二进制中搜索 call gadget_trap 的地址
    # 通常 check_password 中会有一个 call gadget_trap
    # 我们可以通过 CFG 的调用关系找到

    print("\n=== CFG 调用关系 ===")
    for edge in cfg.graph.edges():
        src = edge[0]
        dst = edge[1]
        if src.addr and dst.addr:
            src_func = cfg.kb.functions.floor_func(src.addr)
            dst_func = cfg.kb.functions.floor_func(dst.addr)
            if src_func and dst_func:
                if dst_func.name == "gadget_trap":
                    print(f"  {hex(src.addr)} 调用了 gadget_trap")
                    trap_call_addr = src.addr
                if dst_func.name == "printf":
                    # 检查这个调用块的前驱，看是否引用了 "Success"
                    pass

    print(f"\n=== 关键地址总结 ===")
    if trap_func:
        print(f"avoid 地址 (gadget_trap 入口): {hex(trap_func.addr)}")
    if trap_call_addr:
        print(f"avoid 地址 (调用 gadget_trap 的块): {hex(trap_call_addr)}")

if __name__ == "__main__":
    find_addrs("./crackme")
