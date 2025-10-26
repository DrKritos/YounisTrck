YounisTrck - Elite Vulnerability Scanner v10.4

![D.S](https://yt3.ggpht.com/HsdGfhnRd3IwvpRgS1sPmlINmnj0bDvNi0xKp6qZv1e7Y0LXScRymPitXUIRTev0bJkBDwswjg)  

🔍 Overview

YounisTrck is an advanced, AI-powered vulnerability scanner designed for comprehensive penetration testing and cybersecurity assessments. It combines reconnaissance, vulnerability detection, and threat intelligence in a single tool, supporting both automated and interactive scanning modes.

Key Features:

· Full-Spectrum Scanning: DNS, WHOIS, GeoIP, NMAP, Subdomains
· OWASP Top 10 Coverage: SQLi, XSS, LFI, Command Injection, SSRF, XXE
· Bug Bounty Ready: Checks for misconfigurations, missing headers, and sensitive files
· Multi-Threaded: Fast scanning with concurrent requests (up to 50 threads)
· AI-Powered Detection: Advanced pattern matching for zero-day vulnerabilities
· Comprehensive Reporting: Detailed vulnerability reports with risk levels

---

🚀 Quick Start

Installation

```bash
# Clone the repository
git clone https://github.com/DrKritos/YounisTrck.git
cd YounisTrck

# Ok with the device
python3 YounisTrck-Installer.py

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x YsMhAJi.py
```

Basic Usage

```bash
# Quick scan
python3 YsMhAJi.py http://example.com

# Full comprehensive scan
python3 YsMhAJi.py http://example.com -f

# Interactive mode
python3 YsMhAJi.py
```

---

📋 Features

🔍 Reconnaissance

· DNS Lookup - Comprehensive DNS record analysis
· WHOIS Information - Domain registration details
· GeoIP Location - IP geolocation and ISP information
· Server Banner Grabbing - Service identification and version detection
· NMAP Port Scanning - Advanced port scanning with service detection
· Subdomain Discovery - Extensive subdomain enumeration
· Reverse IP Lookup - Find domains sharing the same IP

🛡️ Vulnerability Detection

· SQL Injection - Advanced SQLi detection with multiple payload types
· Cross-Site Scripting (XSS) - Comprehensive XSS vulnerability testing
· Local File Inclusion (LFI) - File inclusion and path traversal detection
· Remote Code Execution - Command injection and code execution vulnerabilities
· Server-Side Request Forgery (SSRF) - Internal service access testing
· XML External Entity (XXE) - XML parsing vulnerabilities
· API Security Testing - REST and GraphQL endpoint security

🔒 Security Headers & Configurations

· CSP Check - Content Security Policy validation
· HSTS Verification - HTTP Strict Transport Security checks
· Clickjacking Protection - X-Frame-Options and frame busting
· CORS Misconfigurations - Cross-Origin Resource Sharing issues
· Information Disclosure - Server information leakage prevention

🎯 Advanced Capabilities

· AI-Powered Detection - Machine learning pattern recognition
· Multi-Threaded Scanning - High-performance concurrent scanning
· Tor Network Support - Anonymous scanning capabilities
· Comprehensive Reporting - Detailed PDF and text reports
· API Security Testing - Modern API vulnerability assessment
· Cloud Security - AWS, Azure, GCP security checks
· Container Security - Docker and Kubernetes security assessment

---

🛠 Installation Guide

Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip nmap whois

# Termux (Android)
pkg update
pkg install python nmap whois

# Windows (WSL)
# Use Ubuntu WSL distribution
```

Full Installation

```bash
# Clone repository
git clone https://github.com/DrKritos/YounisTrck.git
cd YounisTrck

# Install Python dependencies
pip3 install requests beautifulsoup4 python-nmap python-whois paramiko cryptography dnspython ipaddress

# Alternative: Install from requirements
pip3 install -r requirements.txt

# Make script executable
chmod +x YsMhAJi.py
```

Required Packages

· nmap - Network scanning and service detection
· whois - Domain information lookup
· python-nmap - Python NMAP integration
· requests - HTTP requests library
· beautifulsoup4 - HTML parsing
· paramiko - SSH vulnerability testing
· cryptography - SSL/TLS analysis
· dnspython - DNS record lookup

---

📖 Usage Examples

Basic Scanning

```bash
# Simple target scan
python3 YsMhAJi.py http://target.com

# Scan with Tor for anonymity
python3 YsMhAJi.py http://target.com --tor

# Save results to file
python3 YsMhAJi.py http://target.com --save
```

Advanced Scanning

```bash
# Full comprehensive scan (recommended)
python3 YsMhAJi.py http://target.com -f

# Reconnaissance only
python3 YsMhAJi.py http://target.com -r

# Vulnerability assessment only
python3 YsMhAJi.py http://target.com -v

# Subdomain enumeration
python3 YsMhAJi.py http://target.com -s
```

Interactive Mode

```bash
python3 YsMhAJi.py
```

Then follow the interactive menu:

· Enter target URL
· Choose scanning options
· Select individual modules
· Generate comprehensive reports

---

🔧 Command Line Options

Option Description Example
-f, --full Full comprehensive scan python3 YsMhAJi.py -f http://target.com
-r, --recon Reconnaissance only python3 YsMhAJi.py -r http://target.com
-v, --vuln Vulnerability scans only python3 YsMhAJi.py -v http://target.com
-s, --subdomains Subdomain scanning python3 YsMhAJi.py -s http://target.com
-a, --admin Admin panel discovery python3 YsMhAJi.py -a http://target.com
--tor Use Tor network python3 YsMhAJi.py --tor http://target.com
--save Save results to file python3 YsMhAJi.py --save http://target.com
-c, --crawl Website crawling python3 YsMhAJi.py -c http://target.com

---

📊 Scan Phases

Phase 1: Advanced Reconnaissance

· DNS record analysis (A, AAAA, MX, NS, TXT, CNAME, SOA)
· WHOIS domain registration information
· Geographic IP localization and ISP details
· Service banner collection and version detection
· Comprehensive NMAP port scanning
· Subdomain discovery with extensive wordlist
· Reverse IP lookup for shared hosting analysis

Phase 2: Vulnerability Assessment

· SQL injection testing with 50+ payload variants
· Cross-site scripting (XSS) detection
· Local file inclusion (LFI) and path traversal
· Remote command execution vulnerabilities
· Server-side request forgery (SSRF) testing
· XML external entity (XXE) injection
· API security endpoint testing

Phase 3: Security Configuration

· Security headers validation (CSP, HSTS, X-Frame-Options)
· SSL/TLS configuration analysis
· CORS policy misconfigurations
· Information disclosure prevention
· Authentication and session management

Phase 4: Advanced Threat Detection

· Cloud security misconfigurations (AWS, Azure, GCP)
· Container security (Docker, Kubernetes)
· API security (REST, GraphQL)
· Modern web application vulnerabilities
· Zero-day pattern detection

Phase 5: Reporting & Analysis

· Comprehensive vulnerability reporting
· Risk level classification (CRITICAL, HIGH, MEDIUM, LOW, INFO)
· Detailed findings with evidence
· Remediation recommendations
· Executive summary for stakeholders

---

🎯 Why Choose YounisTrck?

🚀 Performance

· Multi-threaded Architecture - Scan multiple targets simultaneously
· Optimized Algorithms - Fast pattern matching and detection
· Resource Efficient - Low memory footprint and CPU usage

🔍 Comprehensive Coverage

· OWASP Top 10 - Complete coverage of critical vulnerabilities
· Zero-Day Detection - AI-powered pattern recognition
· Continuous Updates - Regular vulnerability database updates

🛡️ Enterprise Ready

· Comprehensive Reporting - Detailed PDF and executive reports
· API Integration - REST API for automation
· Compliance Checking - PCI DSS, HIPAA, GDPR security checks

🌐 Multi-Platform Support

· Linux - Native support for all distributions
· Windows - Full compatibility via WSL
· Android - Complete functionality on Termux
· macOS - Native support on Apple systems

---

📝 Sample Output

Vulnerability Report Example

```
=== Vulnerability Scan Report ===
Target: http://example.com
Scan Time: 2025-10-25 11:30:45MP
Scanner: YounisTrck v10.4

[CRITICAL] SQL Injection Detected
URL: http://example.com/login.php
Parameter: username
Payload: ' OR '1'='1
Evidence: MySQL syntax error detected

[HIGH] XSS Vulnerability
URL: http://example.com/search.php
Parameter: query
Payload: <script>alert('XSS')</script>
Evidence: Script executed in response

[MEDIUM] Missing Security Headers
URL: http://example.com/
Issue: Missing Content-Security-Policy header
Recommendation: Implement CSP policy
```

---

🔒 Security & Privacy

Anonymous Scanning

```bash
# Use Tor network for complete anonymity
python3 YsMhAJi.py http://target.com --tor

# Custom proxy support
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=https://proxy:8080
```

Data Protection

· No data collection or telemetry
· Local processing only
· Optional encrypted report storage
· Temporary file cleanup

---

⚠️ Legal Disclaimer

This tool is developed for educational purposes and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before scanning any systems. The developers are not liable for any misuse or damage caused by this software.

Authorized Use Cases:

· Security research and education
· Authorized penetration testing
· Bug bounty programs with permission
· Security awareness training

Prohibited Use Cases:

· Unauthorized system scanning
· Malicious hacking activities
· Network disruption or damage
· Privacy violation

---

🐛 Troubleshooting

Common Issues & Solutions

Issue: NMAP not found

```bash
# Ubuntu/Debian
sudo apt install nmap

# Termux
pkg install nmap

# Windows
# Install via https://nmap.org/download.html
```

Issue: Python module errors

```bash
pip3 install --upgrade pip
pip3 install -r requirements.txt --force-reinstall
```

Issue: Permission denied

```bash
chmod +x YsMhAJi.py
python3 YsMhAJi.py
```

Issue: Tor connection failed

```bash
# Start Tor service
sudo service tor start
# or
tor &
```

Performance Optimization

```bash
# Increase thread count for faster scanning
# Edit SCAN_CONFIG in script to adjust:
# 'max_workers': 100  # Increase for powerful systems

# Reduce timeouts for internal networks
# 'timeouts': {'http': 5, 'https': 5}
```

---

🔄 Updates & Changelog

Version 10.4 Highlights

· AI-Powered Detection - Enhanced machine learning patterns
· Cloud Security - AWS, Azure, GCP security assessments
· API Security - REST and GraphQL comprehensive testing
· Container Security - Docker and Kubernetes vulnerability detection
· Performance - 40% faster scanning algorithms
· Reporting - Enhanced PDF report generation

Version History

· v10.3 - Added advanced API security testing
· v10.2 - Enhanced cloud security checks
· v10.1 - Improved AI detection algorithms
· v10.0 - Major rewrite with multi-threading

---

📞 Support & Community

Official Channels

· GitHub Repository: DrKritos/YounisTrck
· Telegram Support: @yoyns
· YouTube Tutorials: @5d.S
· Email Support: Via Telegram

Documentation

· Full Documentation: GitHub Wiki
· Video Tutorials: YouTube Channel
· Community Forum: Telegram Group

Contributing

We welcome contributions! Please see our Contributing Guidelines for details.

---

📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

Important: This tool is for educational and authorized security testing purposes only. Unauthorized use against systems you don't own is illegal.

---

🌟 Star History

If you find this tool useful, please give it a star on GitHub! ⭐

https://api.star-history.com/svg?repos=DrKritos/YounisTrck&type=Date

---

⚡ Stay Secure • Stay Ethical • Stay Protected ⚡

---

Last Updated: January 2025 | Version: 10.4 | Developer: Younis Mohammed Al Jilani

<!-- SEO Keywords: vulnerability scanner, penetration testing, cybersecurity, web application security, bug bounty, SQL injection, XSS, LFI, security assessment, ethical hacking, penetration testing tools, vulnerability assessment, web security, network security, API security, cloud security -->