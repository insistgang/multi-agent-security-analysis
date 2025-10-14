#!/usr/bin/env python3
"""
优化版网络安全告警智能研判系统 - 单实例启动脚本
防止重复进程，确保只有一个API服务器和一个Web界面在运行
"""
import os
import sys
import time
import signal
import subprocess
import requests
import psutil
from pathlib import Path

def check_existing_processes():
    """检查并终止现有的重复进程"""
    print("🔍 检查现有进程...")

    current_pid = os.getpid()
    killed_count = 0

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['pid'] == current_pid:
                continue

            if proc.info['name'] == 'python.exe' and proc.info['cmdline']:
                cmdline = ' '.join(proc.info['cmdline'])

                # 检查是否是我们的项目进程
                if 'pj2.0' in cmdline or 'src.api.server' in cmdline or 'streamlit run app.py' in cmdline:
                    print(f"🗑️  终止重复进程: PID {proc.info['pid']} - {cmdline[:80]}...")
                    proc.terminate()
                    killed_count += 1

                    # 等待进程终止
                    try:
                        proc.wait(timeout=5)
                    except psutil.TimeoutExpired:
                        proc.kill()

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if killed_count > 0:
        print(f"✅ 已终止 {killed_count} 个重复进程")
        time.sleep(2)  # 等待进程完全终止
    else:
        print("✅ 没有发现重复进程")

    return killed_count

def is_port_available(port):
    """检查端口是否可用"""
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex(('localhost', port))
            return result != 0
    except:
        return False

def start_api_server():
    """启动API服务器"""
    print("\n🚀 启动API服务器...")

    if not is_port_available(8000):
        print("❌ 端口8000已被占用，请检查是否有其他程序占用")
        return None

    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'

    cmd = [sys.executable, "-m", "src.api.server"]

    try:
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding='utf-8',
            bufsize=1,
            cwd=os.getcwd()
        )

        print(f"✅ API服务器已启动，PID: {process.pid}")
        print(f"📍 地址: http://localhost:8000")

        return process

    except Exception as e:
        print(f"❌ API服务器启动失败: {e}")
        return None

def start_web_interface():
    """启动Web界面"""
    print("\n🌐 启动Web界面...")

    if not is_port_available(7777):
        print("❌ 端口7777已被占用，请检查是否有其他程序占用")
        return None

    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        "web_app/app.py",
        "--server.port", "7777",
        "--server.address", "0.0.0.0",
        "--server.headless", "true"
    ]

    try:
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding='utf-8',
            bufsize=1,
            cwd=os.getcwd()
        )

        print(f"✅ Web界面已启动，PID: {process.pid}")
        print(f"📍 地址: http://localhost:7777")

        return process

    except Exception as e:
        print(f"❌ Web界面启动失败: {e}")
        return None

def wait_for_services(api_process, web_process):
    """等待服务启动"""
    print("\n⏳ 等待服务启动...")

    # 等待API服务器
    api_ready = False
    web_ready = False

    for i in range(60):  # 最多等待60秒
        try:
            # 检查API服务器
            if not api_ready and api_process and api_process.poll() is None:
                response = requests.get("http://localhost:8000/api/v1/system/status", timeout=2)
                if response.status_code == 200:
                    api_ready = True
                    print("✅ API服务器已就绪")

            # 检查Web界面
            if not web_ready and web_process and web_process.poll() is None:
                response = requests.get("http://localhost:7777", timeout=2)
                if response.status_code == 200:
                    web_ready = True
                    print("✅ Web界面已就绪")

            if api_ready and web_ready:
                break

        except:
            pass

        time.sleep(1)

    if not api_ready:
        print("⚠️  API服务器启动超时")
    if not web_ready:
        print("⚠️  Web界面启动超时")

def main():
    """主函数"""
    print("=" * 80)
    print("🛡️  网络安全告警智能研判系统 - 单实例启动器")
    print("=" * 80)
    print("🎯 目标: 只启动1个API服务器 + 1个Web界面")
    print("🚫 防止: 重复进程和资源浪费")
    print("=" * 80)

    # 1. 检查并终止现有进程
    killed_count = check_existing_processes()

    # 2. 启动API服务器
    api_process = start_api_server()
    if not api_process:
        print("❌ 无法启动API服务器，退出")
        return

    # 3. 启动Web界面
    web_process = start_web_interface()
    if not web_process:
        print("❌ 无法启动Web界面，退出")
        if api_process:
            api_process.terminate()
        return

    # 4. 等待服务启动
    wait_for_services(api_process, web_process)

    # 5. 显示成功信息
    print("\n" + "=" * 80)
    print("🎉 系统启动成功！")
    print("=" * 80)
    print(f"📍 Web界面: http://localhost:7777")
    print(f"📍 API服务器: http://localhost:8000")
    print(f"📍 API文档: http://localhost:8000/docs")
    print("\n📊 运行状态:")
    print(f"   API服务器: ✅ 运行中 (PID: {api_process.pid})")
    print(f"   Web界面: ✅ 运行中 (PID: {web_process.pid})")
    print(f"   清理的重复进程: {killed_count} 个")
    print("\n💡 使用说明:")
    print("   1. 在浏览器中打开 http://localhost:7777")
    print("   2. 输入安全告警信息进行分析")
    print("   3. 系统将使用真实的Qwen2-7B模型进行威胁评估")
    print("\n🛑 停止系统: 按 Ctrl+C")
    print("=" * 80)

    # 6. 等待用户中断
    try:
        while True:
            time.sleep(1)

            # 检查进程是否还在运行
            if api_process and api_process.poll() is not None:
                print("❌ API服务器意外停止")
                break
            if web_process and web_process.poll() is not None:
                print("❌ Web界面意外停止")
                break

    except KeyboardInterrupt:
        print("\n\n🛑 收到停止信号，正在关闭系统...")

        if api_process:
            print("🔄 正在停止API服务器...")
            api_process.terminate()
            try:
                api_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                api_process.kill()

        if web_process:
            print("🔄 正在停止Web界面...")
            web_process.terminate()
            try:
                web_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                web_process.kill()

        print("✅ 系统已安全关闭")

if __name__ == "__main__":
    main()