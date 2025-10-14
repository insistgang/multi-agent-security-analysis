#!/usr/bin/env python3
"""
修复版网络安全告警智能研判系统启动脚本
解决emoji编码问题，确保真实Qwen2-7B模型正常工作
"""
import os
import sys
import time
import subprocess
import logging
from pathlib import Path

# 设置UTF-8编码
os.environ['PYTHONIOENCODING'] = 'utf-8'

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fixed_system.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def kill_existing_processes():
    """终止现有的Python进程"""
    try:
        import psutil
        current_pid = os.getpid()
        killed_count = 0

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            if proc.info['pid'] == current_pid:
                continue
            if proc.info['name'] == 'python.exe' and proc.info['cmdline']:
                cmdline = ' '.join(proc.info['cmdline'])
                if 'pj2.0' in cmdline or 'src.api.server' in cmdline or 'streamlit' in cmdline:
                    logger.info(f"终止进程: PID {proc.info['pid']}")
                    proc.terminate()
                    killed_count += 1

        if killed_count > 0:
            logger.info(f"已终止 {killed_count} 个进程")
            time.sleep(3)
        return killed_count
    except ImportError:
        logger.warning("psutil未安装，无法自动清理进程")
        return 0

def start_api_server():
    """启动API服务器"""
    logger.info("启动API服务器...")

    cmd = [sys.executable, "-m", "src.api.server"]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding='utf-8',
            bufsize=1
        )

        logger.info(f"API服务器已启动，PID: {process.pid}")
        return process

    except Exception as e:
        logger.error(f"API服务器启动失败: {e}")
        return None

def start_web_interface():
    """启动Web界面"""
    logger.info("启动Web界面...")

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        "web_app/app.py",
        "--server.port", "7777",
        "--server.address", "0.0.0.0"
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding='utf-8',
            bufsize=1
        )

        logger.info(f"Web界面已启动，PID: {process.pid}")
        return process

    except Exception as e:
        logger.error(f"Web界面启动失败: {e}")
        return None

def main():
    """主函数"""
    print("=" * 80)
    print("网络安全告警智能研判系统 - 修复版")
    print("解决emoji编码问题")
    print("=" * 80)

    # 1. 终止现有进程
    killed = kill_existing_processes()

    # 2. 启动API服务器
    api_process = start_api_server()
    if not api_process:
        return

    # 3. 等待API服务器初始化
    logger.info("等待API服务器初始化...")
    time.sleep(30)  # 等待30秒让模型加载

    # 4. 启动Web界面
    web_process = start_web_interface()
    if not web_process:
        api_process.terminate()
        return

    # 5. 显示访问信息
    print("\n" + "=" * 80)
    print("系统启动成功！")
    print("=" * 80)
    print(f"Web界面: http://localhost:7777")
    print(f"API服务器: http://localhost:8000")
    print(f"清理的进程数: {killed}")
    print("\n按Ctrl+C停止系统")
    print("=" * 80)

    # 6. 等待用户中断
    try:
        while True:
            time.sleep(1)
            if api_process.poll() is not None:
                logger.error("API服务器意外停止")
                break
            if web_process.poll() is not None:
                logger.error("Web界面意外停止")
                break
    except KeyboardInterrupt:
        logger.info("正在关闭系统...")
        api_process.terminate()
        web_process.terminate()
        logger.info("系统已关闭")

if __name__ == "__main__":
    main()