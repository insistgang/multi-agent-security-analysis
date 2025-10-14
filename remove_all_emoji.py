#!/usr/bin/env python3
"""
彻底移除所有emoji字符的脚本
"""

import os
import re

def remove_emoji_from_file(file_path):
    """移除文件中的所有emoji字符"""
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags (iOS)
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "]+"
    )

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 移除emoji
        clean_content = emoji_pattern.sub('', content)

        # 移除特定的Unicode字符
        clean_content = re.sub(r'\\U0001f525', '', clean_content)  # 🔥
        clean_content = re.sub(r'\\U0001f680', '', clean_content)  # 🚀
        clean_content = re.sub(r'\\U0001f527', '', clean_content)  # 🔧
        clean_content = re.sub(r'\\U0001f4a1', '', clean_content)  # 💡
        clean_content = re.sub(r'\\U0001f50d', '', clean_content)  # 🔍
        clean_content = re.sub(r'\\U0001f914', '', clean_content)  # 🤔
        clean_content = re.sub(r'\\U0001f6e0', '', clean_content)  # 🛠️
        clean_content = re.sub(r'\\U0001f6d1', '', clean_content)  # 🛑
        clean_content = re.sub(r'\\U0001f525', '', clean_content)  # 🔥

        # 如果有变化，写回文件
        if content != clean_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(clean_content)
            print(f"已清理文件: {file_path}")
            return True
        else:
            print(f"文件无需清理: {file_path}")
            return False
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {e}")
        return False

# 清理主要Python文件
files_to_clean = [
    'src/agents/expert_agent.py',
    'src/analysis/hybrid_reasoning.py',
    'src/agents/multi_agent_system.py',
    'src/api/server.py',
    'web_app/app.py'
]

print("开始清理所有emoji字符...")
for file_path in files_to_clean:
    if os.path.exists(file_path):
        remove_emoji_from_file(file_path)
    else:
        print(f"文件不存在: {file_path}")

print("\n清理完成！")