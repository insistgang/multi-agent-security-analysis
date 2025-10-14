#!/usr/bin/env python3
"""
修复中文文本 - 恢复被错误清理的中文字符
"""

import os

def fix_chinese_text():
    """修复文件中的中文文本"""

    # 需要修复的行
    fixes = {
        'src/agents/expert_agent.py': [
            ('safe_print("[专家智能体] 调用真实Qwen2-7B模型")', 'safe_print("[专家智能体] 调用真实Qwen2-7B模型")'),
            ('safe_print("[EXPERT] 真实模型推理完成")', 'safe_print("[EXPERT] 真实模型推理完成")'),
            ('safe_print("[FALLBACK] 使用模拟推理")', 'safe_print("[FALLBACK] 使用模拟推理")'),
            ('safe_print(f"[ERROR] GPU: {e}")', 'safe_print(f"[ERROR] GPU: {e}")'),
            ('safe_print(f"[ERROR] : {error_msg_clean}")', 'safe_print(f"[ERROR] 模型错误: {error_msg_clean}")'),
            ('logger.info(f" {self.agent_id} ")', 'logger.info(f"专家智能体 {self.agent_id} 初始化成功")'),
            ('logger.error(f": {e}")', 'logger.error(f"专家智能体错误: {e}")'),
            ('logger.warning(f"RAG: {e}")', 'logger.warning(f"RAG错误: {e}")'),
            ('logger.info(f" {field}: {default_value}")', 'logger.info(f"设置默认值 {field}: {default_value}")'),
            ('self.log_action("", {', 'self.log_action("处理完成", {'),
        ]
    }

    # 读取文件
    with open('src/agents/expert_agent.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 应用修复
    for old, new in fixes['src/agents/expert_agent.py']:
        if old in content:
            content = content.replace(old, new)
            print(f"修复: {old} -> {new}")

    # 写回文件
    with open('src/agents/expert_agent.py', 'w', encoding='utf-8') as f:
        f.write(content)

    print("修复了专家智能体中的中文文本")

if __name__ == "__main__":
    fix_chinese_text()