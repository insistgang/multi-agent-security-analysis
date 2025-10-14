#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重启后快速启动指南
确保只运行2个必要进程
"""

import os
import subprocess
import time
from pathlib import Path

def run_command(cmd, cwd=None):
    """运行命令"""
    print(f"执行: {cmd}")
    if cwd:
        print(f"工作目录: {cwd}")
    subprocess.Popen(cmd, shell=True, cwd=cwd)
    time.sleep(2)

def main():
    print("🚀 网络安全预警分析系统 - 简化启动")
    print("=" * 50)

    # 获取项目路径
    project_path = Path(__file__).parent

    # 步骤1：检查是否有残留进程
    print("\n1️⃣ 检查并清理残留进程...")
    os.system('taskkill /F /IM python.exe 2>nul')
    os.system('taskkill /F /IM streamlit.exe 2>nul')
    time.sleep(3)

    # 步骤2：启动API服务器（端口8000）
    print("\n2️⃣ 启动API服务器...")
    run_command("python -m src.api.server --port 8000", project_path)

    # 步骤3：等待API服务器启动
    print("\n3️⃣ 等待API服务器启动...")
    time.sleep(10)

    # 步骤4：启动Web界面（端口7777）
    print("\n4️⃣ 启动Web界面...")
    web_path = project_path / "web_app"
    run_command("streamlit run app.py --server.port 7777 --server.address 0.0.0.0", web_path)

    print("\n✅ 启动完成！")
    print("\n访问地址:")
    print("- Web界面: http://localhost:7777")
    print("- API文档: http://localhost:8000/docs")
    print("\n按Ctrl+C停止服务")

    # 保持运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 正在停止服务...")

if __name__ == "__main__":
    main()