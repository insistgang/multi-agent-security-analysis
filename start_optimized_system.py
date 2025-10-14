#!/usr/bin/env python3
"""
优化版网络安全告警智能研判系统 - 真实Qwen2-7B模型版本
解决emoji编码问题，确保系统稳定运行
"""
import os
import sys
import time
import logging
import subprocess
from pathlib import Path

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('optimized_system.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def clear_existing_processes():
    """清理现有的Python进程"""
    try:
        import psutil
        current_pid = os.getpid()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['pid'] == current_pid:
                    continue
                if proc.info['name'] == 'python.exe' and proc.info['cmdline']:
                    cmdline = ' '.join(proc.info['cmdline'])
                    if 'pj2.0' in cmdline:
                        logger.info(f"终止进程: PID {proc.info['pid']} - {cmdline}")
                        proc.terminate()
                        proc.wait(timeout=5)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except ImportError:
        logger.warning("psutil未安装，无法清理进程")

def check_dependencies():
    """检查依赖"""
    required_packages = ['torch', 'transformers', 'streamlit', 'fastapi', 'uvicorn']
    missing = []

    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    if missing:
        logger.error(f"缺少依赖包: {missing}")
        logger.info("请运行: pip install -r requirements.txt")
        return False

    return True

def check_model():
    """检查模型文件"""
    model_path = Path("models/Qwen2-7B")
    if not model_path.exists():
        logger.error(f"模型路径不存在: {model_path}")
        logger.info("请确保Qwen2-7B模型已下载到models/Qwen2-7B目录")
        return False

    # 检查关键文件
    required_files = ["config.json", "pytorch_model-00001-of-00004.bin"]
    for file in required_files:
        if not (model_path / file).exists():
            logger.error(f"缺少模型文件: {model_path / file}")
            return False

    logger.info(f"模型检查通过: {model_path}")
    return True

def start_api_server():
    """启动API服务器"""
    logger.info("=" * 80)
    logger.info("启动优化版网络安全告警智能研判系统")
    logger.info("真实Qwen2-7B模型版本")
    logger.info("=" * 80)

    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env['CUDA_VISIBLE_DEVICES'] = '0'

    cmd = [
        sys.executable, "-m", "src.api.server",
        "--host", "0.0.0.0",
        "--port", "8000"
    ]

    logger.info(f"启动API服务器: {' '.join(cmd)}")
    logger.info(f"服务地址: http://localhost:8000")

    try:
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding='utf-8',
            bufsize=1
        )

        # 实时输出日志
        for line in process.stdout:
            print(line.rstrip())

            # 检查启动成功
            if "Application startup complete" in line:
                logger.info("API服务器启动成功！")
                logger.info("真实Qwen2-7B模型已加载")
                logger.info("请在浏览器中访问: http://localhost:8000")
                return process

    except KeyboardInterrupt:
        logger.info("收到中断信号，正在关闭服务器...")
        process.terminate()
        return None
    except Exception as e:
        logger.error(f"启动失败: {e}")
        return None

def start_web_interface():
    """启动Web界面"""
    logger.info("\n启动Web界面...")

    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        "web_app/app.py",
        "--server.port", "7777",
        "--server.address", "0.0.0.0",
        "--server.headless", "true"
    ]

    logger.info(f"启动Web界面: {' '.join(cmd)}")
    logger.info(f"界面地址: http://localhost:7777")

    try:
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding='utf-8',
            bufsize=1
        )

        # 等待Web界面启动
        time.sleep(5)
        logger.info("Web界面启动成功！")
        logger.info("请在浏览器中访问: http://localhost:7777")

        return process

    except Exception as e:
        logger.error(f"Web界面启动失败: {e}")
        return None

def main():
    """主函数"""
    print("\n" + "=" * 80)
    print("优化版网络安全告警智能研判系统")
    print("真实Qwen2-7B模型版本")
    print("=" * 80)

    # 1. 清理现有进程
    logger.info("\n[1/5] 清理现有进程...")
    clear_existing_processes()
    time.sleep(2)

    # 2. 检查依赖
    logger.info("\n[2/5] 检查系统依赖...")
    if not check_dependencies():
        return

    # 3. 检查模型
    logger.info("\n[3/5] 检查模型文件...")
    if not check_model():
        return

    # 4. 启动API服务器
    logger.info("\n[4/5] 启动API服务器...")
    api_process = start_api_server()

    if not api_process:
        logger.error("API服务器启动失败")
        return

    # 5. 启动Web界面
    logger.info("\n[5/5] 启动Web界面...")
    web_process = start_web_interface()

    # 等待用户中断
    try:
        logger.info("\n系统运行中... 按Ctrl+C停止")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\n正在关闭系统...")

        if api_process:
            api_process.terminate()
        if web_process:
            web_process.terminate()

        logger.info("系统已关闭")

if __name__ == "__main__":
    main()