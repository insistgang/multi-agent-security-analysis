#!/usr/bin/env python3
"""
立即修复脚本 - 无需重启系统
解决emoji编码问题和重复进程问题
"""

import sys
import os
import psutil
import subprocess
import time
import signal
import requests
from typing import List, Dict

print("🔧 开始立即修复系统...")

# 1. 强制设置编码环境
print("\n📝 步骤1: 设置编码环境")
os.environ['PYTHONIOENCODING'] = 'utf-8'
os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'
os.environ['LANG'] = 'en_US.UTF-8'
os.environ['LC_ALL'] = 'en_US.UTF-8'

# 2. 查找并终止所有相关进程
print("\n🔍 步骤2: 查找并终止重复进程")

def find_related_processes() -> List[Dict]:
    """查找所有相关进程"""
    target_processes = []
    all_processes = psutil.process_iter(['pid', 'name', 'cmdline'])

    for proc in all_processes:
        try:
            cmdline = ' '.join(proc.info['cmdline'] or [])
            if any(keyword in cmdline.lower() for keyword in [
                'python', 'streamlit', 'src/api/server', 'web_app/app.py',
                'llm_inference', 'hybrid_reasoning', 'expert_agent'
            ]) and ('pj2.0' in cmdline or 'src' in cmdline or 'web_app' in cmdline):
                target_processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': cmdline
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return target_processes

def terminate_process(pid: int, force: bool = False) -> bool:
    """终止指定进程"""
    try:
        proc = psutil.Process(pid)
        if force:
            proc.kill()
        else:
            proc.terminate()

        # 等待进程结束
        try:
            proc.wait(timeout=5)
            return True
        except psutil.TimeoutExpired:
            if not force:
                return terminate_process(pid, force=True)
            return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return True

# 查找所有相关进程
processes = find_related_processes()
print(f"找到 {len(processes)} 个相关进程:")

for proc in processes:
    print(f"  PID: {proc['pid']}, 命令: {proc['cmdline'][:100]}...")

# 终止所有进程
print("\n⚡ 步骤3: 终止所有重复进程")
terminated_count = 0
for proc in processes:
    if terminate_process(proc['pid']):
        print(f"✓ 已终止 PID {proc['pid']}")
        terminated_count += 1
    else:
        print(f"✗ 无法终止 PID {proc['pid']}")

print(f"\n已终止 {terminated_count} 个进程")

# 等待进程完全退出
print("\n⏳ 等待进程完全退出...")
time.sleep(3)

# 3. 检查端口占用
print("\n🔍 步骤4: 检查端口占用")
def check_port(port: int) -> bool:
    """检查端口是否被占用"""
    try:
        response = requests.get(f"http://localhost:{port}", timeout=1)
        return False
    except:
        return True

ports_to_check = [8000, 7777, 8501, 5000]
for port in ports_to_check:
    if check_port(port):
        print(f"✓ 端口 {port} 可用")
    else:
        print(f"⚠ 端口 {port} 仍被占用")

# 4. 启动干净的系统
print("\n🚀 步骤5: 启动干净的系统")

# 启动API服务器
print("启动API服务器...")
api_process = subprocess.Popen([
    sys.executable, '-m', 'src.api.server', '--port', '8000'
], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')

# 等待API服务器启动
print("等待API服务器启动...")
time.sleep(5)

# 检查API服务器状态
try:
    response = requests.get("http://localhost:8000/health", timeout=5)
    if response.status_code == 200:
        print("✓ API服务器启动成功")
    else:
        print("⚠ API服务器状态异常")
except:
    print("⚠ API服务器连接失败")

# 启动Web界面
print("启动Web界面...")
web_process = subprocess.Popen([
    sys.executable, '-m', 'streamlit', 'run', 'web_app/app.py',
    '--server.port', '7777',
    '--server.address', '0.0.0.0'
], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')

print("\n🎉 立即修复完成！")
print("\n📊 系统状态:")
print(f"  - API服务器: PID {api_process.pid}")
print(f"  - Web界面: PID {web_process.pid}")
print(f"  - 终止的重复进程: {terminated_count} 个")

print("\n🌐 访问地址:")
print("  - Web界面: http://localhost:7777")
print("  - API文档: http://localhost:8000/docs")

print("\n💡 如果仍有问题，请检查:")
print("  1. 防火墙设置")
print("  2. GPU驱动程序")
print("  3. Python依赖包")

# 保存进程信息以便后续管理
with open('active_processes.txt', 'w', encoding='utf-8') as f:
    f.write(f"API_SERVER_PID={api_process.pid}\n")
    f.write(f"WEB_INTERFACE_PID={web_process.pid}\n")
    f.write(f"START_TIME={time.strftime('%Y-%m-%d %H:%M:%S')}\n")

print("\n✅ 进程信息已保存到 active_processes.txt")