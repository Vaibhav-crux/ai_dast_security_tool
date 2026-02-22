#!/usr/bin/env python3
"""
Test nmap integration for AutoDAST
"""

import os
import sys
from pathlib import Path

def test_nmap_direct():
    """Test direct nmap executable"""
    print("Testing direct nmap executable...")
    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    
    if os.path.exists(nmap_path):
        print(f"✅ nmap found at: {nmap_path}")
        return True
    else:
        print(f"❌ nmap not found at: {nmap_path}")
        return False

def test_python_nmap():
    """Test python-nmap package"""
    print("\nTesting python-nmap package...")
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        version = nm.nmap_version()
        print(f"✅ python-nmap working with nmap version: {version}")
        return True
    except Exception as e:
        print(f"❌ python-nmap error: {e}")
        return False

def test_port_scan_module():
    """Test the port scan module"""
    print("\nTesting port scan module...")
    try:
        from modules.port_scan import PortScanner
        scanner = PortScanner("localhost", "test_output")
        print("✅ PortScanner initialized successfully")
        return True
    except Exception as e:
        print(f"❌ PortScanner error: {e}")
        return False

def main():
    print("AutoDAST Nmap Integration Test")
    print("=" * 40)
    
    tests = [
        ("Direct nmap", test_nmap_direct),
        ("Python-nmap", test_python_nmap),
        ("Port scan module", test_port_scan_module)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    print(f"\n{'='*40}")
    print("TEST RESULTS")
    print(f"{'='*40}")
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<20} {status}")
        if result:
            passed += 1
    
    print(f"\nSummary: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🎉 All nmap integration tests passed!")
        return True
    else:
        print("⚠️  Some tests failed. Check the output above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 