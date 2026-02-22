#!/usr/bin/env python3
"""
Tool Testing Script for AutoVAPT
Tests all penetration testing tools to ensure they work correctly
"""

import subprocess
import os
import sys
from pathlib import Path

def test_tool(tool_name, tool_path, test_args=None):
    """Test a tool and return success status"""
    print(f"\n{'='*50}")
    print(f"Testing {tool_name}")
    print(f"{'='*50}")
    
    if not os.path.exists(tool_path):
        print(f"❌ {tool_name} not found at: {tool_path}")
        return False
    
    try:
        # Test with --help or -h to check if tool works
        if test_args:
            cmd = [tool_path] + test_args
        else:
            cmd = [tool_path, "--help"]
        
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 or result.returncode == 1:  # Most tools return 1 for help
            print(f"✅ {tool_name} is working correctly!")
            if result.stdout:
                print(f"Output preview: {result.stdout[:200]}...")
            return True
        else:
            print(f"❌ {tool_name} failed with return code: {result.returncode}")
            if result.stderr:
                print(f"Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"❌ {tool_name} timed out")
        return False
    except Exception as e:
        print(f"❌ {tool_name} error: {str(e)}")
        return False

def main():
    """Main function to test all tools"""
    print("AutoVAPT Tool Testing Script")
    print("=" * 50)
    
    # Define tool paths based on your directory structure
    tools = {
        "subfinder": "Tools/subfinder_2.7.1_windows_amd64/subfinder.exe",
        "amass": "Tools/amass_Windows_amd64_2/amass_Windows_amd64/amass.exe",
        "gobuster": "Tools/gobuster_Windows_x86_64/gobuster.exe",
        "dalfox": "Tools/dalfox_2.11.0_windows_amd64/dalfox.exe",
        "nmap": "nmap"  # Assuming nmap is in PATH
    }
    
    working_tools = []
    failed_tools = []
    
    for tool_name, tool_path in tools.items():
        if test_tool(tool_name, tool_path):
            working_tools.append(tool_name)
        else:
            failed_tools.append(tool_name)
    
    # Summary
    print(f"\n{'='*50}")
    print("TESTING SUMMARY")
    print(f"{'='*50}")
    print(f"✅ Working tools ({len(working_tools)}): {', '.join(working_tools)}")
    print(f"❌ Failed tools ({len(failed_tools)}): {', '.join(failed_tools)}")
    
    if failed_tools:
        print(f"\n🔧 Recommendations for failed tools:")
        for tool in failed_tools:
            if tool == "masscan":
                print(f"  - {tool}: Download the Windows executable from https://github.com/robertdavidgraham/masscan/releases")
            else:
                print(f"  - {tool}: Check if the executable is properly extracted and not corrupted")
    
    return len(failed_tools) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 