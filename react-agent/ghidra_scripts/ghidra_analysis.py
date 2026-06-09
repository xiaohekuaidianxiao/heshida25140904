# ghidra_scripts/ghidra_analysis.py
import pyghidra
import inspect

def get_ghidra_api(binary_path):
    """启动Ghidra并加载目标二进制文件，返回可用于分析的API对象。"""
    # 启动 pyghidra，它会在后台自动启动 Java 虚拟机并初始化 Ghidra 环境
    pyghidra.start()
    
    # 导入Ghidra的Java API
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.app.util.headless import HeadlessAnalyzer
    from ghidra.app.util.importer import MessageLog
    from ghidra.program.model.listing import Program
    from ghidra.util.task import ConsoleTaskMonitor
    
    # 创建一个临时项目并导入二进制文件
    # 注意：这里的路径需要根据你的实际需求调整，或者作为参数传入
    project_location = "/tmp/ghidra_projects"
    project_name = "temp_project"
    
    # 这部分API调用可能与你的Ghidra版本有关，请查阅官方文档进行调整
    project = ghidra.app.util.headless.HeadlessAnalyzer.createProject(project_location, project_name, True)
    program = project.importProgram(binary_path)
    if program is None:
        raise Exception(f"Failed to import binary: {binary_path}")
    
    # 创建一个FlatProgramAPI对象，它提供了许多方便的API来操作程序
    flat_api = FlatProgramAPI(program)
    
    # 返回必要的组件，以便其他函数使用
    return flat_api, program

def decompile_function(binary_path, function_name):
    """反编译指定函数，返回伪C代码。"""
    flat_api, program = get_ghidra_api(binary_path)
    
    # 获取函数对象
    func = program.getListing().getFunction(function_name)
    if func is None:
        return f"Function '{function_name}' not found."
    
    # 使用Ghidra的DecompInterface进行反编译
    from ghidra.app.decompiler import DecompInterface
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    
    # 执行反编译
    decompiled = decompiler.decompileFunction(func, 30, None)
    if decompiled is None or not decompiled.decompileCompleted():
        return f"Decompilation failed for function '{function_name}'."
    
    return decompiled.getDecompiledFunction().getC()

# 你可以根据需要添加更多分析函数，如 get_function_calls, get_cross_references 等
