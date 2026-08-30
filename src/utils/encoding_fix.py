#!/usr/bin/env python3
"""
编码兼容性修复工具
专门解决Windows GBK环境下Unicode字符编码问题
"""

import sys
import os
import re
import io
from contextlib import redirect_stdout, redirect_stderr

# 设置全局编码兼容性
if sys.platform.startswith('win'):
    # Windows环境下设置UTF-8编码
    import locale

    # 尝试设置控制台编码为UTF-8
    try:
        os.system('chcp 65001 > nul 2>&1')
    except:
        pass

    # 设置环境变量
    os.environ['PYTHONIOENCODING'] = 'utf-8'

    # 重新配置stdout和stderr
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    if hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

def safe_print(*args, **kwargs):
    """安全的打印函数，避免编码错误"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        # 如果编码失败，清理emoji字符后重试
        cleaned_args = []
        for arg in args:
            if isinstance(arg, str):
                cleaned_args.append(clean_emoji_characters(arg))
            else:
                cleaned_args.append(arg)

        try:
            print(*cleaned_args, **kwargs)
        except UnicodeEncodeError:
            # 如果还是失败，使用ASCII编码
            ascii_args = []
            for arg in cleaned_args:
                if isinstance(arg, str):
                    ascii_args.append(arg.encode('ascii', 'ignore').decode('ascii'))
                else:
                    ascii_args.append(arg)
            print(*ascii_args, **kwargs)

def clean_emoji_characters(text: str) -> str:
    """清理文本中的emoji字符，避免Windows GBK编码错误"""
    if not isinstance(text, str):
        return text

    # 定义emoji字符的正则表达式模式
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # 表情符号
        "\U0001F300-\U0001F5FF"  # 符号和象形文字
        "\U0001F680-\U0001F6FF"  # 交通和地图符号
        "\U0001F700-\U0001F77F"  # 炼金术符号
        "\U0001F780-\U0001F7FF"  # 几何形状扩展
        "\U0001F800-\U0001F8FF"  # 补充箭头-C
        "\U0001F900-\U0001F9FF"  # 补充符号和象形文字
        "\U0001FA00-\U0001FA6F"  # 棋盘符号
        "\U0001FA70-\U0001FAFF"  # 符号和象形文字扩展
        "\U00002702-\U000027B0"  # 装饰符号
        "\U000024C2-\U0001F251"  # 各种符号
        "]+",
        flags=re.UNICODE
    )

    # 替换emoji字符为空字符串
    cleaned_text = emoji_pattern.sub('', text)

    # 进一步清理可能有问题的Unicode字符
    # 只保留ASCII字符 + 基本中文字符
    cleaned_text = ''.join(char for char in cleaned_text
                          if ord(char) < 128 or  # ASCII
                             (ord(char) >= 0x4e00 and ord(char) <= 0x9fff))  # 基本中文

    return cleaned_text

def safe_string_operation(operation_func, fallback_value=""):
    """安全的字符串操作装饰器"""
    def wrapper(*args, **kwargs):
        try:
            return operation_func(*args, **kwargs)
        except UnicodeEncodeError:
            return fallback_value
        except Exception as e:
            safe_print(f"[ERROR] String operation failed: {e}")
            return fallback_value
    return wrapper

def initialize_encoding_compatibility():
    """初始化编码兼容性"""
    safe_print("[INFO] 初始化编码兼容性...")

    # 设置全局编码
    if sys.platform.startswith('win'):
        os.environ['PYTHONIOENCODING'] = 'utf-8'

        # 尝试配置控制台
        try:
            import ctypes
            import ctypes.wintypes

            # 获取控制台句柄
            kernel32 = ctypes.windll.kernel32
            STD_OUTPUT_HANDLE = -11
            STD_ERROR_HANDLE = -12

            # 设置控制台输出模式
            kernel32.SetConsoleMode(kernel32.GetStdHandle(STD_OUTPUT_HANDLE), 7)
            kernel32.SetConsoleMode(kernel32.GetStdHandle(STD_ERROR_HANDLE), 7)
        except:
            pass

    safe_print("[SUCCESS] 编码兼容性初始化完成")

# 初始化编码兼容性
initialize_encoding_compatibility()