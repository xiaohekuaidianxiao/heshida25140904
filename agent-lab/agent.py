"""
agent.py — ReAct 主循环（修复版）
"""

import json
import re
import os
from openai import OpenAI
from tools import controlled_explore, solve_input
import datetime

# sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
# sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# ==============================================================
# 配置
# ==============================================================
BINARY_PATH  = "./crackme"

SUCCESS_ADDR = [0x4011eb]    # puts("Success!") 前的基本块
AVOID_ADDR   = [0x401156]    # gadget_trap 函数入口

# LLM 配置 —— 按你的环境修改
# LLM 配置 —— MiMo API
LLM_BASE_URL = "https://api.xiaomimimo.com/v1"
LLM_API_KEY  = "sk-**************************"
LLM_MODEL    = "mimo-v2.5-pro"


MAX_ROUNDS   = 10
# 改为：用时间戳避免文件冲突
LOG_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(LOG_DIR, f"run_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")


# ==============================================================
# 系统提示词（优化版）
# ==============================================================
SYSTEM_PROMPT = """你是一个二进制逆向分析 Agent。你的任务是找到 crackme 程序的正确输入。

## 规则
1. 每轮必须且只能调用一个工具
2. 不要自行猜测答案，必须通过工具求解
3. 不要输出 "Action: none" 或 "Action: report"，只使用下面列出的两个工具
4. 当 Observation 显示 success: true 时，任务完成

## 可用工具
- controlled_explore：探索程序路径，返回路径统计
- solve_input：从成功路径状态中求解具体输入值

## 输出格式（严格遵守）
Thought: <你的推理>
Action: <controlled_explore 或 solve_input>

## 分析策略（严格按顺序执行 3 步）

### 第 1 步：初步探索
使用 controlled_explore 探索程序，观察路径统计（found/avoided/deadended 数量），
判断是否存在到达目标的路径。

### 第 2 步：路径分析与验证
根据第 1 步的结果，分析程序的分支结构。思考：
- 有多少条路径被 deadend？
- avoid 的路径意味着什么？
- 目标路径是否确认可达？
在 Thought 中写出你的分析结论，然后调用 controlled_explore 再次确认。

### 第 3 步：求解输入
前两步已确认路径可达，现在调用 solve_input 从成功状态中求解具体的输入值。

重要：你必须完成以上 3 步，每步一轮，总共至少 3 轮。
"""


# ==============================================================
# LLM 调用
# ==============================================================
client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)


def call_llm(messages):
    resp = client.chat.completions.create(
        model=LLM_MODEL,
        messages=messages,
        temperature=0.1,
        max_tokens=600,
    )
    return resp.choices[0].message.content


# ==============================================================
# 解析 LLM 输出
# ==============================================================
def parse_output(text):
    thought_m = re.search(r"Thought:\s*(.+?)(?=\nAction:|\Z)", text, re.DOTALL)
    action_m  = re.search(r"Action:\s*(\w+)", text)
    return {
        "thought": thought_m.group(1).strip() if thought_m else text.strip(),
        "action":  action_m.group(1).strip()  if action_m  else "none",
        "raw":     text,
    }


# ==============================================================
# 工具派发
# ==============================================================
TOOL_MAP = {
    "controlled_explore": controlled_explore,
    "solve_input": solve_input,
}


def dispatch(action):
    fn = TOOL_MAP.get(action)
    if fn is None:
        return {"error": f"未知工具: {action}。请使用 controlled_explore 或 solve_input"}
    return fn(BINARY_PATH, find_addrs=SUCCESS_ADDR, avoid_addrs=AVOID_ADDR)


# ==============================================================
# 主循环
# ==============================================================
def main():
    print("=" * 60)
    print("ReAct Agent — crackme 自动化逆向分析")
    print("=" * 60)
    print(f"Binary  : {BINARY_PATH}")
    print(f"Find    : {[hex(a) for a in SUCCESS_ADDR]}")
    print(f"Avoid   : {[hex(a) for a in AVOID_ADDR]}")
    print(f"LLM     : {LLM_MODEL}")
    print(f"Log     : {LOG_PATH}")
    print("=" * 60)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": "请开始分析 crackme 程序，找到正确输入。"},
    ]

    log = []

    for rnd in range(1, MAX_ROUNDS + 1):
        print(f"\n{'─' * 60}")
        print(f"Round {rnd}")
        print(f"{'─' * 60}")

        # 1) LLM 思考
        llm_text = call_llm(messages)
        parsed   = parse_output(llm_text)
        print(f"\n[Thought] {parsed['thought']}")
        print(f"[Action]  {parsed['action']}")

        # 2) 如果 LLM 输出了无效工具，提示它重试
        if parsed["action"] not in TOOL_MAP:
            observation = {
                "error": f"无效工具 '{parsed['action']}'。"
                         f"你只能使用 controlled_explore 或 solve_input。"
                         f"请在下一轮严格按格式调用其中一个。"
            }
        else:
            # 3) 执行工具
            observation = dispatch(parsed["action"])

        obs_text = json.dumps(observation, indent=2, ensure_ascii=False)
        print(f"\n[Observation]\n{obs_text}")

        # 4) 记录日志
        log.append({
            "round": rnd,
            "thought": parsed["thought"],
            "action": parsed["action"],
            "observation": observation,
        })

        # 5) 延续对话
        messages.append({"role": "assistant", "content": llm_text})
        messages.append({"role": "user",      "content": f"Observation:\n{obs_text}"})

        # 6) 终止判断：工具已成功求解输入
        if observation.get("success") and observation.get("input_ascii"):
            ans = observation["input_ascii"]
            print(f"\n{'=' * 60}")
            print(f"[OK] 求解成功！正确输入: {ans}")
            print(f"{'=' * 60}")

            # 让 LLM 做最终总结
            messages.append({
                "role": "user",
                "content": f"已求解成功，输入为 '{ans}'。请做最终总结。",
            })
            summary = call_llm(messages)
            print(f"\n[总结]{summary}")
            log.append({"round": "final", "summary": summary})
            break

    # 保存日志
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)
    print(f"\n运行日志已保存 → {LOG_PATH}")


if __name__ == "__main__":
    main()
