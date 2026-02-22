#!/usr/bin/env python3
"""
Tools Configuration for AutoDAST
Defines paths to all penetration testing tools
"""

import os
from pathlib import Path

# Base directory for tools
TOOLS_DIR = Path(__file__).parent / "Tools"

# Tool paths - update these if your directory structure changes
TOOL_PATHS = {
    "subfinder": TOOLS_DIR / "subfinder_2.7.1_windows_amd64" / "subfinder.exe",
    "amass": TOOLS_DIR / "amass_Windows_amd64_2" / "amass_Windows_amd64" / "amass.exe",
    "gobuster": TOOLS_DIR / "gobuster_Windows_x86_64" / "gobuster.exe",
    "dalfox": TOOLS_DIR / "dalfox_2.11.0_windows_amd64" / "dalfox.exe",
    "nmap": Path("C:/Program Files (x86)/Nmap/nmap.exe"),  # Default Windows installation
    "masscan": None  # Not currently available
}

def get_tool_path(tool_name):
    """Get the full path to a tool"""
    if tool_name not in TOOL_PATHS:
        raise ValueError(f"Unknown tool: {tool_name}")
    
    path = TOOL_PATHS[tool_name]
    if path is None:
        raise FileNotFoundError(f"Tool {tool_name} is not configured")
    
    if not path.exists():
        raise FileNotFoundError(f"Tool {tool_name} not found at: {path}")
    
    return str(path)

def setup_nmap_for_python():
    """Setup nmap path for python-nmap package"""
    try:
        import nmap
        nmap_path = get_tool_path("nmap")
        # Set the nmap path for the python-nmap package
        nmap.PortScanner.nmap_path = nmap_path
        return True
    except Exception as e:
        print(f"Warning: Could not setup nmap for python-nmap: {e}")
        return False

def check_tool_availability(tool_name):
    """Check if a tool is available and working"""
    try:
        path = get_tool_path(tool_name)
        return True, path
    except (ValueError, FileNotFoundError) as e:
        return False, str(e)

def get_available_tools():
    """Get list of all available tools"""
    available = {}
    for tool_name in TOOL_PATHS.keys():
        is_available, path_or_error = check_tool_availability(tool_name)
        if is_available:
            available[tool_name] = path_or_error
        else:
            print(f"Warning: {tool_name} - {path_or_error}")
    
    return available

def test_all_tools():
    """Test all tools and return status"""
    import subprocess
    
    results = {}
    for tool_name in TOOL_PATHS.keys():
        is_available, path_or_error = check_tool_availability(tool_name)
        if is_available:
            try:
                # Test with --help
                result = subprocess.run(
                    [path_or_error, "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                results[tool_name] = {
                    "available": True,
                    "path": path_or_error,
                    "working": result.returncode in [0, 1],  # Most tools return 1 for help
                    "error": None
                }
            except Exception as e:
                results[tool_name] = {
                    "available": True,
                    "path": path_or_error,
                    "working": False,
                    "error": str(e)
                }
        else:
            results[tool_name] = {
                "available": False,
                "path": None,
                "working": False,
                "error": path_or_error
            }
    
    return results

def test_python_nmap():
    """Test python-nmap integration"""
    try:
        import nmap
        nmap_path = get_tool_path("nmap")
        nm = nmap.PortScanner()
        nm.nmap_path = nmap_path
        version = nm.nmap_version()
        return True, f"python-nmap working with nmap version {version}"
    except Exception as e:
        return False, f"python-nmap error: {str(e)}"

if __name__ == "__main__":
    print("AutoDAST Tools Configuration")
    print("=" * 40)
    
    # Test all tools
    results = test_all_tools()
    
    print("\nTool Status:")
    for tool_name, status in results.items():
        if status["available"] and status["working"]:
            print(f"✅ {tool_name}: {status['path']}")
        elif status["available"]:
            print(f"⚠️  {tool_name}: Available but not working - {status['error']}")
        else:
            print(f"❌ {tool_name}: {status['error']}")
    
    # Test python-nmap specifically
    print(f"\nTesting python-nmap integration:")
    nmap_working, nmap_message = test_python_nmap()
    if nmap_working:
        print(f"✅ {nmap_message}")
    else:
        print(f"❌ {nmap_message}")
    
    # Summary
    working = sum(1 for s in results.values() if s["available"] and s["working"])
    total = len(results)
    print(f"\nSummary: {working}/{total} tools working correctly") 