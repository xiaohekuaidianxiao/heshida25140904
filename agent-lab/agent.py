"""
agent.py — ReAct 主循环
实现 Thought → Action → Observation 闭环
"""

import re
import json
import time
from openai import OpenAI

from tools import controlled_explore, solve_input

# ============================================================
# 配置
# ============================================================
BINARY_PATH = "./crackme"

# 关键地址（根据第三步的分析结果填入）
# 示例地址，请替换为你的实际值
SUCCESS_ADDR = [0x4011bc]      # printf("Success!") 之前的基本块地址
                                # 或 call puts("Success!") 的地址
AVOID_ADDRS  = [0x401156]      # gadget_trap 函数入口地址
                                # 也可以加上 call gadget_trap 的地址

# LLM 配置
LLM_BASE_URL = "https://api.openai.com/v1"  # OpenAI 兼容接口
LLM_API_KEY  = "your-api-key-here"
LLM_MODEL    = "gpt-4o"

MAX_ROUNDS = 10

# ============================================================
# 系统提示词
# ============================================================
SYSTEM_PROMPT = """你是一个二进制逆向分析助手。你的任务是分析一个 crackme 程序，找到能触发 "Success!" 输出的正确输入。

## 目标程序信息
该程序读取用户输入（最多9个字符），然后调用 check_password 函数进行验证。
程序存在以下路径：
1. 如果第一个字符是 'A'，第二个字符是 'B' → 进入 gadget_trap() 死循环（必须避免）
2. 如果第一个字符是 'A'，第二个字符是 'Z' → 输出 "Success! Flag is found."（目标）
3. 其他情况 → 输出 "Wrong password!"

## 可用工具
你可以使用以下两个工具（请严格按格式调用）：

### 工具1: controlled_explore
- 作用：在指定约束下探索程序路径
- 格式：Action: controlled_explore()
- 说明：使用预配置的 find/avoid 地址进行探索，返回路径统计信息

### 工具2: solve_input
- 作用：从目标状态求解具体输入
- 格式：Action: solve_input()
- 说明：使用预配置的 find/avoid 地址探索并求解输入

## 交互协议
每一轮请按以下格式回复：

Thought: <你的推理过程，分析当前状态，决定下一步>
Action: <工具名>

重要提示：
- 每轮只调用一个工具
- 仔细分析 Observation 结果后再决定下一步
- 如果已经得到具体输入，可以直接报告结果
- 不需要为工具传递地址参数，系统会自动使用预配置的地址"""

# ============================================================
# LLM 调用
# ============================================================
client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)

def call_llm(messages):
    """调用 LLM 获取回复"""
    response = client.chat.completions.create(
        model=LLM_MODEL,
        messages=messages,
        temperature=0.1,      # 低温度保证稳定性
        max_tokens=1000
    )
    return response.choices[0].message.content


# ============================================================
# 解析 LLM 输出
# ============================================================
def parse_llm_output(text):
    """
    从 LLM 输出中提取 Thought 和 Action
    """
    # 提取 Thought
    thought_match = re.search(
        r"Thought:\s*(.+?)(?=\nAction:|\Z)",
        text,
        re.DOTALL
    )
    thought = thought_match.group(1).strip() if thought_match else text

    # 提取 Action
    action_match = re.search(r"Action:\s*(\w+)", text)
    action = action_match.group(1).strip() if action_match else "none"

    return {
        "thought": thought,
        "action": action,
        "raw": text
    }


# ============================================================
# 执行工具
# ============================================================
def execute_tool(action_name):
    """
    根据解析出的 Action 名称调用对应的 angr 工具
    """
    if action_name == "controlled_explore":
        result = controlled_explore(
            BINARY_PATH,
            find_addrs=SUCCESS_ADDR,
            avoid_addrs=AVOID_ADDRS,
            max_steps=100
        )
        return result

    elif action_name == "solve_input":
        result = solve_input(
            BINARY_PATH,
            find_addrs=SUCCESS_ADDR,
            avoid_addrs=AVOID_ADDRS,
            max_steps=100
        )
        return result

    else:
        return {"error": f"未识别的工具: {action_name}"}


# ============================================================
# 格式化 Observation
# ============================================================
def format_observation(tool_result):
    """将工具结果格式化为结构化文本，供 LLM 阅读"""
    return json.dumps(tool_result, indent=2, ensure_ascii=False)


# ============================================================
# ReAct 主循环
# ============================================================
def main():
    print("=" * 60)
    print("ReAct Agent for crackme 分析")
    print("=" * 60)
    print(f"目标程序: {BINARY_PATH}")
    print(f"find 地址: {[hex(a) for a in SUCCESS_ADDR]}")
    print(f"avoid 地址: {[hex(a) for a in AVOID_ADDRS]}")
    print("=" * 60)

    # 初始化对话历史
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "请开始分析程序，找到正确的输入。"}
    ]

    # 运行日志
    log = []

    for round_num in range(1, MAX_ROUNDS + 1):
        print(f"\n{'='*60}")
        print(f"Round {round_num}")
        print(f"{'='*60}")

        # ① 调用 LLM 获取 Thought + Action
        llm_output = call_llm(messages)
        parsed = parse_llm_output(llm_output)

        print(f"\n[Thought]\n{parsed['thought']}")
        print(f"\n[Action]\n{parsed['action']}")

        # ② 执行工具
        tool_result = execute_tool(parsed["action"])
        observation_text = format_observation(tool_result)

        print(f"\n[Observation]\n{observation_text}")

        # ③ 记录日志
        log.append({
            "round": round_num,
            "thought": parsed["thought"],
            "action": parsed["action"],
            "observation": tool_result
        })

        # ④ 将对话延续
        messages.append({"role": "assistant", "content": llm_output})
        messages.append({
            "role": "user",
            "content": f"Observation:\n{observation_text}"
        })

        # ⑤ 检查是否完成
        if tool_result.get("success") and tool_result.get("input_ascii"):
            found_input = tool_result["input_ascii"]
            print(f"\n{'='*60}")
            print(f"✓ 找到正确输入: {found_input}")
            print(f"{'='*60}")

            # 让 LLM 做最终总结
            messages.append({
                "role": "user",
                "content": f"已经求解成功，输入为 '{found_input}'。请做最终总结。"
            })
            final_output = call_llm(messages)
            print(f"\n[最终总结]\n{final_output}")
            log.append({"round": "final", "summary": final_output})
            break

        # 如果 LLM 声称已完成但工具未确认
        if parsed["action"] == "none" or "完成" in parsed["thought"]:
            print("\n[Agent 声称任务完成，但未通过工具验证]")

    # 保存日志
    with open("run.log", "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)
    print("\n运行日志已保存到 run.log")


if __name__ == "__main__":
    main()
