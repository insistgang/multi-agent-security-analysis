#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
演示系统启动脚本
自动打开浏览器展示系统效果
"""

import webbrowser
import time
import os
import sys
from threading import Thread
import subprocess

def open_browser():
    """延迟2秒后打开浏览器"""
    time.sleep(2)
    url = "file:///" + os.path.abspath("index.html").replace("\\", "/")
    print(f"正在打开浏览器: {url}")
    webbrowser.open(url)

def run_streamlit():
    """运行Streamlit演示"""
    print("\n启动Streamlit演示应用...")
    cmd = f"streamlit run demo_app.py --server.port 8888 --server.headless true"
    print(f"执行命令: {cmd}")

    try:
        subprocess.run(cmd, shell=True, check=True)
    except KeyboardInterrupt:
        print("\nStreamlit应用已停止")
    except Exception as e:
        print(f"启动Streamlit失败: {e}")
        print("\n请手动运行以下命令:")
        print("cd web_demo")
        print("streamlit run demo_app.py")

def main():
    print("=" * 80)
    print("    基于多智能体协同的网络安全威胁智能分析系统")
    print("                    演示系统启动器")
    print("=" * 80)

    print("\n请选择演示方式:")
    print("1. HTML静态演示（推荐）")
    print("2. Streamlit动态演示")
    print("3. 两个都启动")

    choice = input("\n请输入选择 (1/2/3): ").strip()

    if choice == "1":
        print("\n正在启动HTML演示...")
        thread = Thread(target=open_browser)
        thread.daemon = True
        thread.start()
        print("HTML演示已启动！请查看浏览器。")
        print("\n按Ctrl+C退出")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n演示已退出")

    elif choice == "2":
        run_streamlit()

    elif choice == "3":
        print("\n同时启动HTML和Streamlit演示...")
        thread = Thread(target=open_browser)
        thread.daemon = True
        thread.start()

        time.sleep(1)
        run_streamlit()

    else:
        print("\n无效选择，启动默认HTML演示...")
        thread = Thread(target=open_browser)
        thread.daemon = True
        thread.start()
        print("\n按Ctrl+C退出")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n演示已退出")

if __name__ == "__main__":
    main()