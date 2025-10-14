#!/usr/bin/env python3
"""
Simple immediate fix script - no restart required
Fix emoji encoding and duplicate process issues
"""

import sys
import os
import psutil
import subprocess
import time
import requests
from typing import List

print("Starting immediate system fix...")

# 1. Force set encoding environment
print("\nStep 1: Setting encoding environment")
os.environ['PYTHONIOENCODING'] = 'utf-8'
os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'
os.environ['LANG'] = 'en_US.UTF-8'
os.environ['LC_ALL'] = 'en_US.UTF-8'

# 2. Find and terminate all related processes
print("\nStep 2: Finding and terminating duplicate processes")

def find_related_processes():
    """Find all related processes"""
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

def terminate_process(pid, force=False):
    """Terminate specified process"""
    try:
        proc = psutil.Process(pid)
        if force:
            proc.kill()
        else:
            proc.terminate()

        # Wait for process to end
        try:
            proc.wait(timeout=5)
            return True
        except psutil.TimeoutExpired:
            if not force:
                return terminate_process(pid, force=True)
            return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return True

# Find all related processes
processes = find_related_processes()
print(f"Found {len(processes)} related processes:")

for proc in processes:
    print(f"  PID: {proc['pid']}, Command: {proc['cmdline'][:100]}...")

# Terminate all processes
print("\nStep 3: Terminating all duplicate processes")
terminated_count = 0
for proc in processes:
    if terminate_process(proc['pid']):
        print(f"  Terminated PID {proc['pid']}")
        terminated_count += 1
    else:
        print(f"  Failed to terminate PID {proc['pid']}")

print(f"\nTerminated {terminated_count} processes")

# Wait for processes to fully exit
print("\nWaiting for processes to fully exit...")
time.sleep(3)

# 3. Check port occupation
print("\nStep 4: Checking port occupation")
def check_port(port):
    """Check if port is occupied"""
    try:
        response = requests.get(f"http://localhost:{port}", timeout=1)
        return False
    except:
        return True

ports_to_check = [8000, 7777, 8501, 5000]
for port in ports_to_check:
    if check_port(port):
        print(f"  Port {port} is available")
    else:
        print(f"  Port {port} is still occupied")

# 4. Start clean system
print("\nStep 5: Starting clean system")

# Import encoding fix first
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'utils'))
try:
    import encoding_fix_forced
    print("  Encoding fix applied")
except ImportError:
    print("  Warning: Could not import encoding fix")

# Start API server
print("Starting API server...")
api_process = subprocess.Popen([
    sys.executable, '-m', 'src.api.server', '--port', '8000'
], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')

# Wait for API server to start
print("Waiting for API server to start...")
time.sleep(5)

# Check API server status
try:
    response = requests.get("http://localhost:8000/health", timeout=5)
    if response.status_code == 200:
        print("  API server started successfully")
    else:
        print("  API server status abnormal")
except:
    print("  API server connection failed")

# Start Web interface
print("Starting Web interface...")
web_process = subprocess.Popen([
    sys.executable, '-m', 'streamlit', 'run', 'web_app/app.py',
    '--server.port', '7777',
    '--server.address', '0.0.0.0'
], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')

print("\nImmediate fix completed!")
print("\nSystem status:")
print(f"  - API server: PID {api_process.pid}")
print(f"  - Web interface: PID {web_process.pid}")
print(f"  - Terminated duplicate processes: {terminated_count}")

print("\nAccess URLs:")
print("  - Web interface: http://localhost:7777")
print("  - API documentation: http://localhost:8000/docs")

print("\nTips if issues persist:")
print("  1. Check firewall settings")
print("  2. Check GPU drivers")
print("  3. Check Python dependencies")

# Save process information for later management
with open('active_processes.txt', 'w', encoding='utf-8') as f:
    f.write(f"API_SERVER_PID={api_process.pid}\n")
    f.write(f"WEB_INTERFACE_PID={web_process.pid}\n")
    f.write(f"START_TIME={time.strftime('%Y-%m-%d %H:%M:%S')}\n")

print("\nProcess information saved to active_processes.txt")