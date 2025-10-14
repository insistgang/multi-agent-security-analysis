"""
终极编码修复方案 - 强制UTF-8编码
解决Windows GBK环境下emoji编码问题
"""

import sys
import os
import locale
import codecs
import re
from typing import Any

# 全局强制设置UTF-8编码
if sys.platform == 'win32':
    # Windows系统强制编码设置
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'

    # 重新配置stdout和stderr
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)
    if hasattr(sys.stderr, 'buffer'):
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)

# 彻底的emoji清理函数
def remove_all_emojis(text: Any) -> str:
    """彻底清除所有emoji字符"""
    if not isinstance(text, str):
        text = str(text)

    # 移除所有Unicode emoji字符
    # 移除表情符号 (Emoticons)
    text = re.sub(r'[\U0001F600-\U0001F64F]', '', text)
    # 移除符号和象形文字 (Symbols & Pictographs)
    text = re.sub(r'[\U0001F300-\U0001F5FF]', '', text)
    # 移击交通和地图符号 (Transport & Map Symbols)
    text = re.sub(r'[\U0001F680-\U0001F6FF]', '', text)
    # 移击其他符号 (Miscellaneous Symbols)
    text = re.sub(r'[\U0001F700-\U0001F77F]', '', text)
    # 移击几何形状扩展 (Geometric Shapes Extended)
    text = re.sub(r'[\U0001F780-\U0001F7FF]', '', text)
    # 移击补充箭头-C (Supplemental Arrows-C)
    text = re.sub(r'[\U0001F800-\U0001F8FF]', '', text)
    # 移击补充符号和象形文字 (Supplemental Symbols and Pictographs)
    text = re.sub(r'[\U0001F900-\U0001F9FF]', '', text)
    # 移击棋盘符号 (Chess Symbols)
    text = re.sub(r'[\U0001FA00-\U0001FA6F]', '', text)
    # 移击符号和象形文字扩展 (Symbols and Pictographs Extended)
    text = re.sub(r'[\U0001FA70-\U0001FAFF]', '', text)

    # 移除其他可能的Unicode问题字符
    text = re.sub(r'[\u2600-\u26FF]', '', text)  # 杂项符号
    text = re.sub(r'[\u2700-\u27BF]', '', text)  # 装饰符号

    return text.strip()

# 安全打印函数
def safe_print_no_emoji(*args, **kwargs):
    """绝对不会出现编码错误的打印函数"""
    try:
        # 尝试正常打印
        print(*args, **kwargs)
    except UnicodeEncodeError:
        # 如果失败，清理所有emoji并重试
        cleaned_args = []
        for arg in args:
            if isinstance(arg, str):
                cleaned_args.append(remove_all_emojis(arg))
            else:
                cleaned_args.append(remove_all_emojis(str(arg)))

        # 强制使用UTF-8编码
        try:
            print(*cleaned_args, **kwargs)
        except Exception:
            # 最后的保险：用ASCII编码
            ascii_args = [str(arg).encode('ascii', 'ignore').decode('ascii') for arg in cleaned_args]
            print(*ascii_args, **kwargs)

# 全局字符串处理函数
def ensure_utf8_safe(text: Any) -> str:
    """确保字符串可以在UTF-8环境下安全使用"""
    if not isinstance(text, str):
        text = str(text)

    # 先清理emoji
    text = remove_all_emojis(text)

    # 确保是有效的UTF-8
    try:
        text.encode('utf-8')
        return text
    except UnicodeEncodeError:
        # 如果仍然有问题，使用ASCII
        return text.encode('ascii', 'ignore').decode('ascii')

# 强制设置环境变量
def force_utf8_environment():
    """强制设置UTF-8环境"""
    os.environ['LANG'] = 'en_US.UTF-8'
    os.environ['LC_ALL'] = 'en_US.UTF-8'
    os.environ['LC_CTYPE'] = 'en_US.UTF-8'
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# 立即执行修复
force_utf8_environment()

# 替换默认的print函数
import builtins
builtins.print = safe_print_no_emoji

print("[编码修复] UTF-8强制编码修复已启用")
print("[编码修复] 所有emoji字符将被自动清理")