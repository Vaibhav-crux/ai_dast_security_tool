#!/usr/bin/env python3
import sys
import os
import importlib
import subprocess
from pathlib import Path

def check_python_version():
    print("Checking Python version...")
    if sys.version_info >= (3, 8):
        print("✓ Python version OK")
        return True
    else:
        print("✗ Python version must be 3.8 or higher")
        return False

def check_dependencies():
    print("\nChecking dependencies...")
    required_packages = [
        'PyQt6',
        'python-dotenv',
        'requests',
        'python-owasp-zap-v2.4',
        'llama_cpp_python',
        'numpy',
        'pandas',
        'fpdf',
        'Jinja2',
        'PyYAML',
        'tqdm'
    ]
    
    all_ok = True
    for package in required_packages:
        try:
            importlib.import_module(package.replace('-', '_'))
            print(f"✓ {package} OK")
        except ImportError as e:
            print(f"✗ {package} not found: {str(e)}")
            all_ok = False
    return all_ok

def check_directories():
    print("\nChecking directories...")
    required_dirs = [
        'scan_results',
        'reports',
        'logs',
        'models',
        'models/cache',
        'assets',
        'assets/icons'
    ]
    
    all_ok = True
    for dir_path in required_dirs:
        if os.path.exists(dir_path) and os.path.isdir(dir_path):
            print(f"✓ {dir_path} exists")
        else:
            print(f"✗ {dir_path} not found")
            all_ok = False
    return all_ok

def check_model():
    print("\nChecking AI model...")
    model_path = Path("models/q4_0-orca-mini-3b.gguf")
    if model_path.exists():
        print("✓ AI model found")
        return True
    else:
        print("✗ AI model not found")
        return False

def check_zap():
    print("\nChecking OWASP ZAP...")
    zap_paths = [
        r"C:\Program Files\ZAP",
        r"C:\Program Files (x86)\ZAP",
        os.getenv("ZAP_PATH", "")
    ]
    
    for path in zap_paths:
        if path and os.path.exists(path):
            print(f"✓ ZAP found at {path}")
            return True
    
    print("✗ OWASP ZAP not found")
    return False

def check_env():
    print("\nChecking environment configuration...")
    if os.path.exists(".env"):
        print("✓ .env file exists")
        return True
    else:
        print("✗ .env file not found")
        return False

def main():
    print("AutoDAST Installation Test\n")
    
    checks = [
        ("Python Version", check_python_version()),
        ("Dependencies", check_dependencies()),
        ("Directories", check_directories()),
        ("AI Model", check_model()),
        ("OWASP ZAP", check_zap()),
        ("Environment", check_env())
    ]
    
    print("\nTest Summary:")
    print("-" * 40)
    all_passed = True
    for name, result in checks:
        status = "PASS" if result else "FAIL"
        all_passed &= result
        print(f"{name:.<30}{status}")
    print("-" * 40)
    
    if all_passed:
        print("\n✓ All checks passed! AutoDAST is ready to use.")
        sys.exit(0)
    else:
        print("\n✗ Some checks failed. Please fix the issues and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main() 