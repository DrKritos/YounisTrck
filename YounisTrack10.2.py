#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YounisTrack Dependency Installer
Automatically installs all required Python packages for YounisTrack v10.4
"""

import sys
import subprocess
import importlib
import platform
import os
from time import sleep

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                   YounisTrack v10.4                          ║
    ║               Dependency Installer Script                   ║
    ║                                                              ║
    ║         AI-Powered Vulnerability Scanner Setup              ║
    ║         Developed by Younis Mohammed Al Jilani              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Check if Python version is compatible"""
    print("[+] Checking Python version...")
    if sys.version_info < (3, 6):
        print("[-] ERROR: Python 3.6 or higher is required!")
        print(f"[-] Current version: {sys.version}")
        sys.exit(1)
    print(f"[+] Python version: {sys.version} - OK")

def run_command(command, check=False):
    """Run shell command and return result"""
    try:
        if check:
            subprocess.run(command, shell=True, check=True, capture_output=True)
        else:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, "", str(e)
    return 0, "", ""

def install_system_dependencies():
    """Install system-level dependencies"""
    system = platform.system().lower()
    
    print(f"\n[+] Installing system dependencies for {system}...")
    
    if system == "linux":
        # Ubuntu/Debian
        if os.path.exists("/etc/debian_version"):
            commands = [
                "sudo apt update",
                "sudo apt install -y python3 python3-pip nmap whois git curl wget",
                "sudo apt install -y build-essential python3-dev libffi-dev libssl-dev"
            ]
        # CentOS/RHEL
        elif os.path.exists("/etc/redhat-release"):
            commands = [
                "sudo yum update -y",
                "sudo yum install -y python3 python3-pip nmap whois git curl wget",
                "sudo yum install -y gcc python3-devel libffi-devel openssl-devel"
            ]
        # Arch Linux
        elif os.path.exists("/etc/arch-release"):
            commands = [
                "sudo pacman -Sy",
                "sudo pacman -S --noconfirm python python-pip nmap whois git curl wget",
                "sudo pacman -S --noconfirm base-devel python-pip"
            ]
        else:
            print("[-] Unsupported Linux distribution")
            return False
    
    elif system == "darwin":  # macOS
        commands = [
            "brew update",
            "brew install python3 nmap whois git curl wget",
            "brew install openssl readline sqlite3 xz zlib"
        ]
    
    elif system == "windows":
        print("[!] On Windows, please install dependencies manually:")
        print("    - Install Python 3.8+ from python.org")
        print("    - Install Nmap from nmap.org")
        print("    - Install Git from git-scm.com")
        return True
    
    else:
        print(f"[-] Unsupported operating system: {system}")
        return False
    
    for cmd in commands:
        print(f"    Running: {cmd}")
        returncode, stdout, stderr = run_command(cmd)
        if returncode != 0:
            print(f"    Warning: Command failed: {cmd}")
            print(f"    Error: {stderr}")
    
    return True

def upgrade_pip():
    """Upgrade pip to latest version"""
    print("\n[+] Upgrading pip...")
    commands = [
        "python3 -m pip install --upgrade pip",
        "pip3 install --upgrade pip"
    ]
    
    for cmd in commands:
        returncode, stdout, stderr = run_command(cmd)
        if returncode == 0:
            print("[+] pip upgraded successfully")
            return True
    
    print("[-] Failed to upgrade pip, but continuing...")
    return False

def install_python_package(package, pip_name=None, import_name=None):
    """Install individual Python package"""
    if pip_name is None:
        pip_name = package
    if import_name is None:
        import_name = package
    
    print(f"    Installing {package}...")
    
    # Try multiple pip commands
    pip_commands = [
        f"pip3 install {pip_name} --upgrade",
        f"python3 -m pip install {pip_name} --upgrade",
        f"pip install {pip_name} --upgrade"
    ]
    
    for cmd in pip_commands:
        returncode, stdout, stderr = run_command(cmd)
        if returncode == 0:
            # Verify installation
            try:
                importlib.import_module(import_name)
                print(f"    ✓ {package} installed successfully")
                return True
            except ImportError:
                print(f"    ✗ {package} installed but import failed")
                return False
    
    print(f"    ✗ Failed to install {package}")
    return False

def install_all_packages():
    """Install all required Python packages"""
    packages = [
        # Core web and networking
        {"package": "requests", "pip_name": "requests", "import_name": "requests"},
        {"package": "BeautifulSoup4", "pip_name": "beautifulsoup4", "import_name": "bs4"},
        {"package": "urllib3", "pip_name": "urllib3", "import_name": "urllib3"},
        
        # DNS and network scanning
        {"package": "dnspython", "pip_name": "dnspython", "import_name": "dns.resolver"},
        {"package": "python-nmap", "pip_name": "python-nmap", "import_name": "nmap"},
        {"package": "python-whois", "pip_name": "python-whois", "import_name": "whois"},
        
        # Security and cryptography
        {"package": "paramiko", "pip_name": "paramiko", "import_name": "paramiko"},
        {"package": "cryptography", "pip_name": "cryptography", "import_name": "cryptography"},
        {"package": "pyOpenSSL", "pip_name": "pyopenssl", "import_name": "OpenSSL"},
        
        # Data processing and utilities
        {"package": "lxml", "pip_name": "lxml", "import_name": "lxml"},
        {"package": "html5lib", "pip_name": "html5lib", "import_name": "html5lib"},
        
        # AI and advanced features (optional)
        {"package": "openai", "pip_name": "openai", "import_name": "openai"},
        {"package": "numpy", "pip_name": "numpy", "import_name": "numpy"},
        {"package": "pandas", "pip_name": "pandas", "import_name": "pandas"},
        
        # Additional utilities
        {"package": "colorama", "pip_name": "colorama", "import_name": "colorama"},
        {"package": "tqdm", "pip_name": "tqdm", "import_name": "tqdm"},
        {"package": "psutil", "pip_name": "psutil", "import_name": "psutil"},
    ]
    
    print("\n[+] Installing Python packages...")
    print("[!] This may take several minutes depending on your internet connection.")
    
    successful_installs = 0
    failed_installs = []
    
    for pkg in packages:
        if install_python_package(pkg["package"], pkg["pip_name"], pkg["import_name"]):
            successful_installs += 1
        else:
            failed_installs.append(pkg["package"])
        sleep(1)  # Be nice to the PyPI servers
    
    return successful_installs, failed_installs

def verify_installations():
    """Verify that all critical packages can be imported"""
    print("\n[+] Verifying installations...")
    
    critical_packages = [
        "requests", "bs4", "dns.resolver", "nmap", "whois",
        "paramiko", "cryptography", "urllib3"
    ]
    
    failed_imports = []
    
    for package in critical_packages:
        try:
            importlib.import_module(package)
            print(f"    ✓ {package} - OK")
        except ImportError as e:
            print(f"    ✗ {package} - FAILED: {e}")
            failed_imports.append(package)
    
    return failed_imports

def create_requirements_file():
    """Create requirements.txt file for future use"""
    requirements = """requests>=2.28.0
beautifulsoup4>=4.11.0
python-nmap>=0.7.1
python-whois>=0.8.0
paramiko>=3.0.0
cryptography>=39.0.0
dnspython>=2.3.0
urllib3>=1.26.0
lxml>=4.9.0
html5lib>=1.1
pyopenssl>=23.0.0
colorama>=0.4.0
tqdm>=4.64.0
psutil>=5.9.0
openai>=0.27.0
numpy>=1.24.0
pandas>=1.5.0
"""
    
    with open("requirements.txt", "w") as f:
        f.write(requirements)
    print("\n[+] Created requirements.txt file")

def main():
    print_banner()
    
    # Check Python version
    check_python_version()
    
    # Install system dependencies
    if not install_system_dependencies():
        print("[-] System dependency installation failed")
        sys.exit(1)
    
    # Upgrade pip
    upgrade_pip()
    
    # Install Python packages
    successful, failed = install_all_packages()
    
    # Verify installations
    failed_imports = verify_installations()
    
    # Create requirements file
    create_requirements_file()
    
    # Print summary
    print("\n" + "="*60)
    print("INSTALLATION SUMMARY")
    print("="*60)
    print(f"Successful installations: {successful}")
    print(f"Failed installations: {len(failed)}")
    
    if failed:
        print("\nFailed packages:")
        for pkg in failed:
            print(f"  - {pkg}")
    
    if failed_imports:
        print("\nPackages that failed import verification:")
        for pkg in failed_imports:
            print(f"  - {pkg}")
    
    if not failed and not failed_imports:
        print("\n🎉 ALL DEPENDENCIES INSTALLED SUCCESSFULLY!")
        print("\nYou can now run YounisTrack with:")
        print("  python3 YsMhAJi.py")
    else:
        print("\n⚠️  Some dependencies failed to install.")
        print("You may need to install them manually:")
        for pkg in failed + failed_imports:
            print(f"  pip3 install {pkg}")
    
    print("\n" + "="*60)
    print("Next steps:")
    print("1. Run the scanner: python3 YsMhAJi.py")
    print("2. Use interactive mode for guided scanning")
    print("3. Check documentation for advanced usage")
    print("="*60)

if __name__ == "__main__":
    main()