#!/usr/bin/env python3
"""
Clean system startup - bypass all encoding issues
Direct startup without problematic imports
"""

import sys
import os
import subprocess
import time
import signal

# Set environment variables first
os.environ['PYTHONIOENCODING'] = 'utf-8'
os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '0'

print("Starting clean system...")

def start_api_server():
    """Start API server with clean environment"""
    print("\nStarting API server on port 8000...")

    # Create a subprocess with clean environment
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env['PYTHONLEGACYWINDOWSSTDIO'] = '0'

    cmd = [sys.executable, '-m', 'src.api.server', '--port', '8000']

    # Start process
    process = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8',
        bufsize=1,
        universal_newlines=True
    )

    return process

def start_web_interface():
    """Start web interface with clean environment"""
    print("\nStarting web interface on port 7777...")

    # Create a subprocess with clean environment
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env['PYTHONLEGACYWINDOWSSTDIO'] = '0'

    cmd = [sys.executable, '-m', 'streamlit', 'run', 'web_app/app.py',
           '--server.port', '7777', '--server.address', '0.0.0.0']

    # Start process
    process = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8',
        bufsize=1,
        universal_newlines=True
    )

    return process

def monitor_process(process, name):
    """Monitor process output"""
    print(f"\nMonitoring {name}...")
    try:
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                # Clean any problematic characters before printing
                clean_output = output.encode('ascii', 'ignore').decode('ascii')
                print(f"[{name}] {clean_output.strip()}")
    except Exception as e:
        print(f"Error monitoring {name}: {e}")

if __name__ == "__main__":
    try:
        # Start API server
        api_process = start_api_server()
        print(f"API server started with PID: {api_process.pid}")

        # Wait a bit for API server to initialize
        time.sleep(3)

        # Start web interface
        web_process = start_web_interface()
        print(f"Web interface started with PID: {web_process.pid}")

        # Save PIDs
        with open('clean_system_pids.txt', 'w') as f:
            f.write(f"API_PID={api_process.pid}\n")
            f.write(f"WEB_PID={web_process.pid}\n")
            f.write(f"START_TIME={time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        print("\n" + "="*50)
        print("CLEAN SYSTEM STARTED SUCCESSFULLY!")
        print("="*50)
        print(f"API Server PID: {api_process.pid}")
        print(f"Web Interface PID: {web_process.pid}")
        print("\nAccess URLs:")
        print("  - Web Interface: http://localhost:7777")
        print("  - API Health: http://localhost:8000/health")
        print("  - API Docs: http://localhost:8000/docs")
        print("\nPress Ctrl+C to stop all services")
        print("="*50)

        # Monitor both processes
        import threading

        api_thread = threading.Thread(target=monitor_process, args=(api_process, "API"))
        web_thread = threading.Thread(target=monitor_process, args=(web_process, "WEB"))

        api_thread.daemon = True
        web_thread.daemon = True

        api_thread.start()
        web_thread.start()

        # Keep main thread alive
        try:
            while True:
                time.sleep(1)

                # Check if processes are still running
                if api_process.poll() is not None:
                    print("API server has stopped!")
                    break

                if web_process.poll() is not None:
                    print("Web interface has stopped!")
                    break

        except KeyboardInterrupt:
            print("\n\nShutting down...")

            # Terminate processes
            try:
                api_process.terminate()
                web_process.terminate()

                # Wait for graceful shutdown
                time.sleep(2)

                # Force kill if still running
                if api_process.poll() is None:
                    api_process.kill()
                if web_process.poll() is None:
                    web_process.kill()

                print("All services stopped.")

            except Exception as e:
                print(f"Error during shutdown: {e}")

    except Exception as e:
        print(f"Error starting system: {e}")
        import traceback
        traceback.print_exc()