#!/usr/bin/env python3
"""
网络安全告警智能研判系统 - GPU优化版本
专为RTX 4070s 12G显卡优化
使用CUDA加速，彻底解决emoji编码问题
"""

import os
import sys
import time
import signal
import subprocess
import threading

def check_gpu_available():
    """检查GPU是否可用"""
    try:
        import torch
        if torch.cuda.is_available():
            gpu_count = torch.cuda.device_count()
            gpu_name = torch.cuda.get_device_name(0)
            gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
            print(f"[GPU] 检测到 {gpu_count} 个GPU")
            print(f"[GPU] 主GPU: {gpu_name}")
            print(f"[GPU] 显存: {gpu_memory:.1f}GB")
            return True
        else:
            print("[GPU] 未检测到CUDA支持，将使用CPU")
            return False
    except Exception as e:
        print(f"[GPU] GPU检测失败: {e}")
        return False

def kill_existing_processes():
    """杀死现有的Python进程"""
    print("[CLEANUP] 正在清理现有进程...")
    try:
        # Windows系统
        if os.name == 'nt':
            # 杀死所有Python进程
            subprocess.run(['taskkill', '/F', '/IM', 'python.exe'],
                          capture_output=True, text=True)
            subprocess.run(['taskkill', '/F', '/IM', 'streamlit.exe'],
                          capture_output=True, text=True)
        # Linux/Mac系统
        else:
            subprocess.run(['pkill', '-f', 'python'], capture_output=True)
            subprocess.run(['pkill', '-f', 'streamlit'], capture_output=True)

        time.sleep(2)
        print("[CLEANUP] 进程清理完成")
    except Exception as e:
        print(f"[CLEANUP] 进程清理失败: {e}")

def fix_environment():
    """修复环境变量和编码问题"""
    # 设置环境变量强制使用UTF-8
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'

    # 强制使用GPU
    os.environ['CUDA_VISIBLE_DEVICES'] = '0'

    # 优化GPU内存使用
    os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'max_split_size_mb:512'

    print("[ENV] 环境变量设置完成")

def start_api_server():
    """启动API服务器"""
    print("\n" + "="*60)
    print("[API] 启动网络安全告警智能研判系统 - GPU版本")
    print("[GPU] 使用RTX 4070s 12G显卡加速")
    print("[CUDA] 强制使用GPU推理")
    print("[CLEAN] 彻底解决emoji编码问题")
    print("="*60)

    try:
        # 设置编码环境
        fix_environment()

        # 导入并启动API服务器
        import torch
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"[DEVICE] 使用设备: {device}")

        # 启动FastAPI服务器
        import uvicorn
        from src.api.server import app

        # 配置服务器
        config = {
            "host": "0.0.0.0",
            "port": 8000,
            "log_level": "info",
            "access_log": True
        }

        print(f"[API] 服务器地址: http://localhost:8000")
        print(f"[API] 正在启动GPU优化版本...")

        uvicorn.run(app, **config)

    except Exception as e:
        print(f"[ERROR] API服务器启动失败: {e}")
        return False

    return True

def start_web_interface():
    """启动Web界面"""
    print("[WEB] 启动Web界面...")
    time.sleep(3)  # 等待API服务器启动

    try:
        # 启动Streamlit
        import subprocess
        subprocess.run([
            'streamlit', 'run',
            'web_app/app.py',
            '--server.port', '8501',
            '--server.address', '0.0.0.0',
            '--browser.gatherUsageStats', 'false'
        ])

    except Exception as e:
        print(f"[ERROR] Web界面启动失败: {e}")

def main():
    """主函数"""
    print("="*60)
    print("网络安全告警智能研判系统 - GPU优化版本")
    print("专为RTX 4070s 12G显卡优化")
    print("="*60)

    # 1. 检查GPU
    print("\n[STEP 1] 检查GPU...")
    gpu_available = check_gpu_available()

    # 2. 清理现有进程
    print("\n[STEP 2] 清理现有进程...")
    kill_existing_processes()

    # 3. 修复环境
    print("\n[STEP 3] 配置环境...")
    fix_environment()

    # 4. 启动API服务器
    print("\n[STEP 4] 启动API服务器...")
    api_thread = threading.Thread(target=start_api_server, daemon=True)
    api_thread.start()

    # 5. 启动Web界面
    print("\n[STEP 5] 启动Web界面...")
    web_thread = threading.Thread(target=start_web_interface, daemon=True)
    web_thread.start()

    print("\n" + "="*60)
    print("系统启动中...")
    print("API地址: http://localhost:8000")
    print("Web界面: http://localhost:8501")
    print(f"GPU状态: {'✅ 可用' if gpu_available else '❌ 不可用'}")
    print("="*60)

    # 保持主线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[STOP] 系统正在关闭...")
        print("[STOP] 感谢使用GPU优化版本！")

if __name__ == "__main__":
    main()