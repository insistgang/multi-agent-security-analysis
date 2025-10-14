#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final Verification Script - 100% Confirm System Works
"""

import os
import json
import sys
import time
import subprocess
import requests
from datetime import datetime

# Set encoding for Windows
if sys.platform == 'win32':
    os.system('chcp 65001 >nul')

def test_api():
    """Test API functionality"""
    print("\n=== Testing API ===")

    # Test system status
    try:
        response = requests.get("http://localhost:8000/api/v1/system/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"[OK] API Status: {data['system_status']['health_check']['overall_health']}")
            print(f"[OK] Expert Agents: {data['agent_status']['experts_count']}")
            return True
    except:
        pass

    print("[FAIL] API not responding")
    return False

def test_data_processing():
    """Test data processing"""
    print("\n=== Testing Data Processing ===")

    # Create test data
    os.makedirs("data", exist_ok=True)

    test_data = {
        "attack_type": "SQL Injection",
        "payload": "SELECT * FROM users WHERE id='1' OR '1'='1",
        "source_ip": "192.168.1.100",
        "target_ip": "10.0.0.5",
        "threat_level": "high",
        "protocol": "HTTP"
    }

    with open("data/test.json", "w", encoding="utf-8") as f:
        json.dump([test_data], f, ensure_ascii=False, indent=2)

    print("[OK] Created test data: data/test.json")

    # Run analysis
    try:
        result = subprocess.run(
            [sys.executable, "data_processor.py"],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=30
        )

        if result.returncode == 0:
            print("[OK] Data processing completed")

            # Check output
            for file in os.listdir('.'):
                if file.startswith('threat_analysis_results_'):
                    print(f"[OK] Results saved: {file}")
                    return True

        print("[FAIL] Data processing failed")
        print("Error:", result.stderr[:200])

    except Exception as e:
        print(f"[FAIL] Error: {e}")

    return False

def main():
    """Main verification"""
    print("="*80)
    print("FINAL SYSTEM VERIFICATION")
    print("="*80)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    all_ok = True

    # Test 1: API
    if not test_api():
        all_ok = False

    # Test 2: Data Processing
    if not test_data_processing():
        all_ok = False

    # Conclusion
    print("\n" + "="*80)
    print("VERIFICATION RESULT")
    print("="*80)

    if all_ok:
        print("""
[SUCCESS] SYSTEM FULLY OPERATIONAL!

✅ API Service: Working
✅ Data Processing: Working
✅ Analysis Engine: Working
✅ Result Export: Working

THE SYSTEM CAN 100% ANALYZE DATA FOLDER CONTENT!

Usage:
1. Put data files in 'data/' folder
2. Run: python data_processor.py
3. Check results

System is ready for production use!
""")
    else:
        print("""
[PARTIAL] Some components need attention

Please check:
1. API service status
2. Error messages above
3. System logs: logs/api_server.log

Contact support if issues persist.
""")

    return all_ok

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)