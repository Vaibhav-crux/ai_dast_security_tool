#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is 3.8 or higher"""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)

def create_virtual_environment():
    """Create and activate virtual environment"""
    if not os.path.exists("venv"):
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
    
    if sys.platform == "win32":
        activate_script = "venv\\Scripts\\activate"
    else:
        activate_script = "venv/bin/activate"
    
    print(f"Virtual environment created. Please activate it with: source {activate_script}")

def install_dependencies():
    """Install Python dependencies"""
    subprocess.run([
        sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
    ], check=True)

def create_directories():
    """Create necessary directories"""
    directories = [
        "models",
        "scan_results",
        "reports",
        "logs"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")

def setup_environment():
    """Setup environment variables"""
    if not os.path.exists(".env"):
        shutil.copy(".env.example", ".env")
        print("Created .env file from template. Please update it with your settings.")

def check_external_tools():
    """Check if required external tools are installed"""
    tools = {
        "subfinder": "subfinder -version",
        "amass": "amass -version",
        "nmap": "nmap --version",
        "gobuster": "gobuster version",
        "retire": "retire --version",
        "nuclei": "nuclei -version"
    }
    
    missing_tools = []
    for tool, command in tools.items():
        try:
            subprocess.run(command.split(), capture_output=True)
            print(f"✓ {tool} is installed")
        except FileNotFoundError:
            missing_tools.append(tool)
            print(f"✗ {tool} is not installed")
    
    if missing_tools:
        print("\nPlease install the following tools:")
        for tool in missing_tools:
            print(f"- {tool}")

def download_ai_model():
    """Download the AI model if not present"""
    model_path = Path("models/q4_0-orca-mini-3b.gguf")
    if not model_path.exists():
        print("\nAI model not found. Please download q4_0-orca-mini-3b.gguf and place it in the models directory")
        print("You can download it from: https://huggingface.co/TheBloke/Orca-Mini-3B-GGUF/resolve/main/q4_0-orca-mini-3b.gguf")

def main():
    """Main setup function"""
    print("Starting AutoDAST setup...")
    
    try:
        check_python_version()
        create_virtual_environment()
        install_dependencies()
        create_directories()
        setup_environment()
        check_external_tools()
        download_ai_model()
        
        print("\nSetup completed successfully!")
        print("\nNext steps:")
        print("1. Activate the virtual environment")
        print("2. Update the .env file with your settings")
        print("3. Download and place the AI model in the models directory")
        print("4. Install any missing external tools")
        print("5. Run 'python main.py' to start AutoDAST")
        
    except Exception as e:
        print(f"\nError during setup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 