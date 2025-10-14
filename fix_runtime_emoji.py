#!/usr/bin/env python3
"""
运行时emoji修复 - 在专家智能体中强制清理所有Unicode字符
"""

import os
import re

def fix_expert_agent():
    """修复专家智能体的运行时emoji问题"""

    # 读取文件
    with open('src/agents/expert_agent.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 替换第228行的打印语句
    old_line = '            safe_print("[] Qwen2-7B")'
    new_line = '            safe_print("[专家智能体] 调用真实Qwen2-7B模型")'
    content = content.replace(old_line, new_line)

    # 替换第329行的打印语句
    old_line = '        safe_print(f"\\n[] Qwen2-7B")'
    new_line = '        safe_print(f"\\n[专家智能体] 开始调用Qwen2-7B模型")'
    content = content.replace(old_line, new_line)

    # 替换第346行的打印语句
    old_line = '            safe_print("[EXPERT] Real model inference completed")'
    new_line = '            safe_print("[EXPERT] 真实模型推理完成")'
    content = content.replace(old_line, new_line)

    # 替换第352行的打印语句
    old_line = '            safe_print("[FALLBACK] ")'
    new_line = '            safe_print("[FALLBACK] 使用模拟推理")'
    content = content.replace(old_line, new_line)

    # 写回文件
    with open('src/agents/expert_agent.py', 'w', encoding='utf-8') as f:
        f.write(content)

    print("修复了专家智能体中的所有运行时emoji问题")

if __name__ == "__main__":
    fix_expert_agent()