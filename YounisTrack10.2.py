#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YounisTrck - Welcome & Donation Script
Developed by: Younis Mohammed Al Jilani
"""

import os
import sys
import time
from datetime import datetime

# Colors for printing
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print welcome banner"""
    banner = f"""
{Colors.CYAN}
╔══════════════════════════════════════════════════════════════╗
║{Colors.BOLD}{Colors.YELLOW}                  YounisTrck v10.4 - يونس تراك                {Colors.CYAN}║
║                                                              ║
║ {Colors.WHITE}🚀 Advanced Vulnerability Scanner - AI Powered{Colors.CYAN}               ║
║ {Colors.WHITE}🔍 Comprehensive Security Assessment Tool{Colors.CYAN}                    ║
║                                                              ║
║ {Colors.GREEN}👤 Developer: Younis Mohammed Al Jilani{Colors.CYAN}                      ║
║ {Colors.GREEN}📧 Contact: https://wa.me/+967775991458 on WhatsApp{Colors.CYAN}                               ║
║                                                              ║
║ {Colors.BLUE}📱 Telegram: https://t.me/yoyns{Colors.CYAN}                               ║
║ {Colors.BLUE}🎥 YouTube: https://www.youtube.com/@5d.S{Colors.CYAN}                     ║
║ {Colors.BLUE}📂 GitHub: https://github.com/DrKritos/YounisTrck{Colors.CYAN}             ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def print_donation_section():
    """Donation information section"""
    donation_text = f"""
{Colors.PURPLE}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                     🎗️ PROJECT SUPPORT 🎗️                    ║
║                    Support the Developer                    ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.YELLOW}📦 Why Support?{Colors.END}
{Colors.WHITE}• Continuous development and updates
• Adding new features and advanced protection
• User support and assistance
• Developing free security tools for the community

{Colors.YELLOW}💰 How to Support?{Colors.END}
{Colors.GREEN}You can support project continuity by donating via:{Colors.END}

{Colors.CYAN}{Colors.BOLD}🎯 Payeer Wallet:{Colors.END}
{Colors.WHITE}➤ {Colors.RED}{Colors.BOLD}P1087373730{Colors.END}

{Colors.YELLOW}📲 Donation Steps:{Colors.END}
{Colors.WHITE}1. Open Payeer application
2. Choose "Send Money"
3. Enter wallet number: {Colors.RED}P1087373730{Colors.WHITE}
4. Select amount and currency
5. Confirm transaction

{Colors.GREEN}🤝 Thank You for Your Support{Colors.END}
{Colors.WHITE}Every donation helps in tool development and adding new features
for community and security benefits

{Colors.CYAN}✨ May God Reward You for Your Support ✨{Colors.END}
"""

    print(donation_text)

def print_features():
    """Tool features"""
    features = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                       TOOL FEATURES                         ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.YELLOW}🔍 Security Scanning:{Colors.END}
{Colors.WHITE}✓ SQL Injection Detection
✓ Cross-Site Scripting (XSS)
✓ Local File Inclusion (LFI)
✓ Remote Code Execution
✓ Server-Side Request Forgery (SSRF)

{Colors.YELLOW}🌐 Reconnaissance:{Colors.END}
{Colors.WHITE}✓ DNS Information Gathering
✓ WHOIS Lookup
✓ Port Scanning with NMAP
✓ Subdomain Discovery
✓ Server Banner Grabbing

{Colors.YELLOW}🛡️ Advanced Protection:{Colors.END}
{Colors.WHITE}✓ AI-Powered Threat Detection
✓ API Security Testing
✓ Cloud Security Assessment
✓ Container Security Checks
✓ Comprehensive Reporting

{Colors.YELLOW}⚡ Performance:{Colors.END}
{Colors.WHITE}✓ Multi-threaded Scanning
✓ Fast Vulnerability Detection
✓ Interactive Mode
✓ Detailed Risk Assessment
"""

    print(features)

def main():
    """Main function"""
    clear_screen()
    
    # Print welcome banner
    print_banner()
    
    # Wait 2 seconds
    time.sleep(2)
    
    # Print features
    print_features()
    
    # Wait 3 seconds
    time.sleep(3)
    
    # Print donation section
    print_donation_section()
    
    # Footer
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.WHITE}Thank you for using YounisTrck!{Colors.END}")
    print(f"{Colors.GREEN}Start scanning: python3 YsMhAJi.py{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")

if __name__ == "__main__":
    main()