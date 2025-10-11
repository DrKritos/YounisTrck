# YounisTrack - YsMhAJi - Elite Vulnerability Scanner v10.3

![D.S](https://yt3.ggpht.com/HsdGfhnRd3IwvpRgS1sPmlINmnj0bDvNi0xKp6qZv1e7Y0LXScRymPitXUIRTev0bJkBDwswjg)  
**By [@Yoyns](https://t.me/mtmanag)** | **Telegram:** [t.me/mtmanag](https://t.me/mtmanag)  

---

## 🔍 Overview
**YounisTrack** is an advanced, AI-powered vulnerability scanner designed for comprehensive penetration testing and cybersecurity assessments. It combines reconnaissance, vulnerability detection, and threat intelligence in a single tool, supporting both automated and interactive scanning modes.  

Key Features:  
- **Full-Spectrum Scanning**: DNS, WHOIS, GeoIP, NMAP, and more.  
- **OWASP Top 10 Coverage**: SQLi, XSS, LFI, Command Injection, etc.  
- **Bug Bounty Ready**: Checks for misconfigurations, missing headers, and sensitive files.  
- **Multi-Threaded**: Fast scanning with concurrent requests.  
- **Reporting**: Detailed vulnerability reports with risk levels.  

---

## 🚀 Installation
```bash
git clone https://github.com/DrKritos/YounisTrack.git
cd YounisTrack
pip3 install -r requirements.txt
chmod +x YsMhAJi.py
```

**Requirements**:  
- Python 3.8+  
- `nmap`, `whois`, `paramiko`, `requests`, `beautifulsoup4`, `cryptography`, `ipaddress`, `openai`

---

## 🛠 Usage
### Basic Scan
```bash
python3 YsMhAJi.py http://example.com
```

### Full Scan (Recon + Vuln + Crawling)
```bash
python3 YsMhAJi.py http://example.com -f
```

### Interactive Mode
```bash
python3 YsMhAJi.py
```
*(Follow the menu prompts)*  

### Options
| Flag          | Description                          |
|---------------|--------------------------------------|
| `-f`          | Full scan (all phases)               |
| `-r`          | Reconnaissance only                  |
| `-v`          | Vulnerability scans only             |
| `--tor`       | Use Tor network                      |
| `--save`      | Save report to `*`   |

---

## 📊 Scan Phases
1. **Reconnaissance**: DNS, WHOIS, GeoIP, NMAP, Subdomains.  
2. **Vulnerability Assessment**: SQLi, XSS, LFI, Command Injection, PHP configs.  
3. **Post-Exploitation**: Check for backdoors, netcat, and sensitive paths.  
4. **Reporting**: Generate detailed reports with risk levels (CRITICAL to INFO).  

---

## 🌟 Why YounisTrack?
- **AI-Powered**: Uses pattern matching for zero-day vulnerabilities.  
- **Compliance Checks**: Validates security headers (CSP, HSTS).  
- **Multi-Platform**: Works on Linux, Windows (WSL), and Android (Termux).  
- **Privacy**: Optional Tor support for anonymous scanning.  

---

## 📜 License
**Disclaimer**: For authorized penetration testing only. Unethical use is prohibited.  

---

## 📬 Contact
**Developer**: [@yoyns](https://t.me/mtmanag)  
**Telegram Channel**: [t.me/mtmanag](https://t.me/mtmanag)  
**YouTube Channel**: [youtube.com/@5D.S](https://www.youtube.com/channel/UCmlNoySt8O0JkC8fAuuQEKQ?sub_confirmation=1)  

```

### SEO Optimization Tips:
1. **Keywords**: Include terms like "vulnerability scanner," "penetration testing," "bug bounty tools," "SQLi/XSS detection."  
2. **Headers**: Use H2/H3 tags for structure (e.g., "## Features," "## Installation").  
3. **Links**: Add GitHub repo link and Telegram for backlinks.  
4. **Images**: Include a banner screenshot (host on Imgur/GitHub).    

Example meta-description:  
```html
<meta name="description" content="YounisTrack - AI-powered vulnerability scanner for pentesters. Detect SQLi, XSS, LFI, and more with automated reporting. Download now.">
```
