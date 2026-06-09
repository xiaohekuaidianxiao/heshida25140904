# ReAct Agent 静态分析实验

## 项目概述
实现一个基于ReAct模式的AI Agent，使用LLM协调 `radare2` 和 `Ghidra` 工具对黑盒ELF二进制文件进行静态分析，以识别潜在的安全漏洞。

## 环境要求
- Python 3.8+
- radare2
- Ghidra (需记录 `analyzeHeadless` 脚本路径)
- 支持Tool Calling的LLM API (如OpenAI)

## 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt

