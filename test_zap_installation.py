import os
import subprocess
import sys

def check_zap_installation():
    """Check ZAP installation and paths"""
    print("Checking ZAP installation...")
    
    # Check ZAP directory
    zap_dir = r"C:\Program Files\ZAP\Zed Attack Proxy"
    if not os.path.exists(zap_dir):
        print(f"Error: ZAP directory not found at {zap_dir}")
        return False
    
    print(f"✓ ZAP directory found at: {zap_dir}")
    
    # Check zap.bat
    zap_bat = os.path.join(zap_dir, "zap.bat")
    if not os.path.exists(zap_bat):
        print(f"Error: zap.bat not found at {zap_bat}")
        return False
    
    print(f"✓ zap.bat found at: {zap_bat}")
    
    # Check ZAP JAR
    zap_jar = os.path.join(zap_dir, "zap-2.16.1.jar")
    if not os.path.exists(zap_jar):
        print(f"Error: ZAP JAR not found at {zap_jar}")
        return False
    
    print(f"✓ ZAP JAR found at: {zap_jar}")
    
    # Check Java installation
    try:
        java_version = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT)
        print("✓ Java is installed")
        print(f"Java version output:\n{java_version.decode()}")
    except Exception as e:
        print(f"Error: Java not found or not working: {str(e)}")
        return False
    
    print("\nZAP installation check completed successfully!")
    return True

if __name__ == "__main__":
    if not check_zap_installation():
        sys.exit(1) 