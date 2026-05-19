#!/usr/bin/env python3
"""
Vulnerability Scanner - Core Logic
Used by both CLI and Web Interface
"""

import socket
import threading
import ssl
import re
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# ============================================================
# DATA
# ============================================================

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')"
]

SQL_PAYLOADS = ["'", "' OR '1'='1", "'; DROP TABLE users; --", "1' OR '1' = '1"]
SQL_ERROR_PATTERNS = ["sql", "mysql", "sql syntax", "ora-", "postgres", "syntax error"]

SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS header missing',
    'Content-Security-Policy': 'CSP header missing',
    'X-Frame-Options': 'Clickjacking protection missing',
    'X-Content-Type-Options': 'MIME sniffing protection missing'
}

COMMON_DIRS = ['admin', 'login', 'wp-admin', 'backup', 'config', 'phpmyadmin', '.git', '.env']


# ============================================================
# NETWORK SCANNER
# ============================================================

class NetworkScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
        self.vulnerabilities = []
        self.resolved_ip = None

    def resolve_hostname(self):
        try:
            self.resolved_ip = socket.gethostbyname(self.target)
            return self.resolved_ip
        except:
            return None

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.resolved_ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                self.open_ports.append({"port": port, "service": service})
            sock.close()
        except:
            pass

    def run_port_scan(self):
        self.open_ports = []
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
        
        threads = []
        for port in ports:
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            if len(threads) >= 20:
                for t in threads:
                    t.join()
                threads = []
        for t in threads:
            t.join()
        
        return self.open_ports

    def check_weak_configs(self):
        vulnerabilities = []
        for p in self.open_ports:
            if p['port'] == 21:
                vulnerabilities.append({"type": "Insecure FTP", "severity": "HIGH", "description": "FTP sends credentials in plaintext", "remediation": "Use SFTP or FTPS"})
            elif p['port'] == 23:
                vulnerabilities.append({"type": "Telnet Enabled", "severity": "CRITICAL", "description": "Telnet is completely insecure", "remediation": "Disable Telnet, use SSH"})
            elif p['port'] == 445:
                vulnerabilities.append({"type": "SMB Service", "severity": "HIGH", "description": "Vulnerable to EternalBlue", "remediation": "Apply patches, disable SMBv1"})
            elif p['port'] == 80:
                vulnerabilities.append({"type": "HTTP Not HTTPS", "severity": "MEDIUM", "description": "Traffic is unencrypted", "remediation": "Enable HTTPS"})
        return vulnerabilities

    def scan(self):
        if not self.resolve_hostname():
            return {"error": f"Cannot resolve {self.target}"}
        
        ports = self.run_port_scan()
        weak_configs = self.check_weak_configs()
        
        return {
            "target": self.target,
            "ip": self.resolved_ip,
            "scan_time": datetime.now().isoformat(),
            "open_ports": ports,
            "vulnerabilities": weak_configs,
            "total_vulnerabilities": len(weak_configs),
            "scan_type": "network"
        }


# ============================================================
# WEB SCANNER
# ============================================================

class WebScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Vulnerability-Scanner'})
        self.vulnerabilities = []

    def check_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            missing = []
            for header, desc in SECURITY_HEADERS.items():
                if header not in headers:
                    missing.append(desc)
            if missing:
                self.vulnerabilities.append({
                    "type": "Missing Security Headers",
                    "severity": "MEDIUM",
                    "description": f"Missing: {', '.join(missing[:3])}",
                    "remediation": "Add security headers to HTTP responses"
                })
            
            if 'Server' in headers:
                self.vulnerabilities.append({
                    "type": "Server Version Disclosure",
                    "severity": "LOW",
                    "description": f"Server: {headers['Server']}",
                    "remediation": "Hide or obfuscate server version"
                })
        except Exception as e:
            self.vulnerabilities.append({
                "type": "Connection Error",
                "severity": "INFO",
                "description": f"Could not connect: {str(e)[:100]}",
                "remediation": "Check URL and network connectivity"
            })

    def check_common_dirs(self):
        found = []
        for directory in COMMON_DIRS:
            test_url = urljoin(self.target_url, f'/{directory}')
            try:
                response = self.session.get(test_url, timeout=3, verify=False)
                if response.status_code == 200:
                    found.append(directory)
                    self.vulnerabilities.append({
                        "type": "Sensitive Directory Found",
                        "severity": "MEDIUM",
                        "description": f"Directory accessible: /{directory}",
                        "remediation": "Restrict access to admin/backup directories"
                    })
            except:
                pass
        return found

    def check_robots(self):
        robots_url = urljoin(self.target_url, '/robots.txt')
        try:
            response = self.session.get(robots_url, timeout=5, verify=False)
            if response.status_code == 200:
                disallowed = re.findall(r'Disallow:\s*(.+)', response.text)
                if disallowed:
                    self.vulnerabilities.append({
                        "type": "Information Disclosure",
                        "severity": "LOW",
                        "description": f"robots.txt exposes {len(disallowed)} paths",
                        "remediation": "Review robots.txt content"
                    })
        except:
            pass

    def test_sql_injection(self):
        test_params = {"id": "1", "q": "test", "search": "query"}
        for param, value in test_params.items():
            for payload in SQL_PAYLOADS:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5, verify=False)
                    for pattern in SQL_ERROR_PATTERNS:
                        if pattern in response.text.lower():
                            self.vulnerabilities.append({
                                "type": "SQL Injection",
                                "severity": "CRITICAL",
                                "description": f"Potential SQLi in parameter '{param}'",
                                "remediation": "Use parameterized queries"
                            })
                            return
                except:
                    pass

    def test_xss(self):
        for payload in XSS_PAYLOADS:
            try:
                test_url = f"{self.target_url}?q={payload}"
                response = self.session.get(test_url, timeout=5, verify=False)
                if payload in response.text:
                    self.vulnerabilities.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "description": f"Reflected XSS with payload: {payload[:30]}",
                        "remediation": "Implement output encoding"
                    })
                    return
            except:
                pass

    def scan(self):
        self.vulnerabilities = []
        
        self.check_headers()
        self.check_robots()
        self.check_common_dirs()
        self.test_sql_injection()
        self.test_xss()
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in self.vulnerabilities:
            s = v.get('severity', 'LOW')
            if s in severity_counts:
                severity_counts[s] += 1
        
        return {
            "target_url": self.target_url,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": self.vulnerabilities,
            "severity_counts": severity_counts,
            "total_vulnerabilities": len(self.vulnerabilities),
            "scan_type": "web"
        }


# For direct testing
if __name__ == "__main__":
    # Test network scan
    ns = NetworkScanner("scanme.nmap.org")
    result = ns.scan()
    print(f"Network Scan: {len(result.get('open_ports', []))} ports open")
    
    # Test web scan
    ws = WebScanner("http://testphp.vulnweb.com")
    result = ws.scan()
    print(f"Web Scan: {result['total_vulnerabilities']} vulnerabilities found")