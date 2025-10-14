#!/usr/bin/env python3
"""
Loguru编码修复 - 避免Windows GBK编码问题
"""

import sys
import os
from loguru import logger

# 移除默认处理器
logger.remove()

# 添加安全的控制台处理器 - 只输出ASCII字符
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO",
    colorize=False,
    backtrace=True,
    diagnose=False,
    catch=True
)

# 添加安全的文件处理器 - 使用UTF-8编码
os.makedirs("logs", exist_ok=True)
logger.add(
    "logs/system.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
    level="DEBUG",
    rotation="10 MB",
    retention="7 days",
    compression="zip",
    encoding="utf-8",
    catch=True
)

# 创建安全的日志记录函数
def safe_log_info(message: str, **kwargs):
    """安全的info日志记录"""
    try:
        # 清理emoji字符
        clean_message = ''.join(c for c in str(message) if ord(c) < 128)
        if kwargs:
            clean_kwargs = {k: ''.join(c for c in str(v) if ord(c) < 128) for k, v in kwargs.items()}
            logger.info(f"{clean_message} {clean_kwargs}")
        else:
            logger.info(clean_message)
    except Exception:
        logger.info("Log message encoding error")

def safe_log_error(message: str, **kwargs):
    """安全的error日志记录"""
    try:
        # 清理emoji字符
        clean_message = ''.join(c for c in str(message) if ord(c) < 128)
        if kwargs:
            clean_kwargs = {k: ''.join(c for c in str(v) if ord(c) < 128) for k, v in kwargs.items()}
            logger.error(f"{clean_message} {clean_kwargs}")
        else:
            logger.error(clean_message)
    except Exception:
        logger.error("Log message encoding error")

def safe_log_warning(message: str, **kwargs):
    """安全的warning日志记录"""
    try:
        # 清理emoji字符
        clean_message = ''.join(c for c in str(message) if ord(c) < 128)
        if kwargs:
            clean_kwargs = {k: ''.join(c for c in str(v) if ord(c) < 128) for k, v in kwargs.items()}
            logger.warning(f"{clean_message} {clean_kwargs}")
        else:
            logger.warning(clean_message)
    except Exception:
        logger.warning("Log message encoding error")

# 导出安全的日志函数
__all__ = ['logger', 'safe_log_info', 'safe_log_error', 'safe_log_warning']