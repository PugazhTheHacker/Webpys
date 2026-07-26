#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WebPyS v3.o.1 - Web Reconnaissance & Passive Scanner
Author: Pugazhenthi
License: MIT
"""

import socket
import ssl
import requests
import re
import sys
import subprocess
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse
from xml.etree.ElementTree import Element, SubElement, ElementTree
from rich.console import Console
from rich import print

# ---- CONFIG ----
USER_AGENT = "WebPyS Scanner v2.1"
HTTP_TIMEOUT = 5
PORTS = [80, 443,554]
SUBDOMAINS = ["www", "mail", "dev", "admin", "test", "api", "webmail"]
console = Console()

# ---- BANNER ----
def print_banner():
    console.print("[bold orange3]\n"
                  " __        __   _     ____        _     \n"
                  " \\ \\      / /__| |__ |  _ \\ _   _| |__  \n"
                  "  \\ \\ /\\ / / _ \\ '_ \\| |_) | | | | '_ \\ \n"
                  "   \\ V  V /  __/ |_) |  __/| |_| | |_) |\n"
                  "    \\_/\\_/ \\___|_.__/|_|    \\__,_|_.__/ \n"
                  "\n[/bold orange3]"
                  "[bold cyan]      WebPyS v2.1 - Website Scanner[/bold cyan]\n"
                  "[bold white]         Author: Pugazhexploit[/bold white]\n\n"
                  "[bright_blue]  =====================================[/bright_blue]\n"
                  "[bold orange1]    Passive Recon | SSL | Headers[/bold orange1]\n"
                  "[bright_blue]  =====================================[/bright_blue]\n"
                  "[green]        [+] Use It At Your Own Risk[/green]\n")

# ---- VALIDATION ----
def is_valid_domain(domain):
    return bool(re.match(r"^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$", domain))

# ---- DNS ----
def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"[red][!] DNS resolution failed for {domain}[/red]")
        return None

# ---- PORT CHECK ----
def check_ports(domain):
    results = {}
    for port in PORTS:
        try:
            with socket.create_connection((domain, port), timeout=3):
                results[port] = "Open"
        except:
            results[port] = "Closed"
    return results

# ---- SSL CERT INFO ----
def get_ssl_info(domain):
    ssl_info = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info = {
                    "subject": cert.get("subject", []),
                    "issuer": cert.get("issuer", []),
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter")
                }
    except Exception as e:
        print(f"[red][!] SSL error: {e}[/red]")
    return ssl_info

# ---- HEADERS ----
def get_headers(url):
    headers = {'User-Agent': USER_AGENT}
    try:
        response = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, verify=True)
        return response.status_code, dict(response.headers)
    except Exception as e:
        print(f"[red][!] Failed to fetch headers from {url}: {e}[/red]")
        return None, {}

# ---- ANALYSIS ----
def analyze_ssl_info(ssl_data):
    issues = []
    if not ssl_data:
        return ["No SSL certificate found. Potential MITM."]
    try:
        expire = datetime.strptime(ssl_data.get("valid_to"), "%b %d %H:%M:%S %Y %Z")
        if expire < datetime.now(timezone.utc):
            issues.append("SSL certificate expired.")
    except:
        issues.append("Error parsing SSL date.")
    return issues

def analyze_http_headers(headers):
    issues = []
    if "Content-Security-Policy" not in headers:
        issues.append("Missing Content-Security-Policy (XSS risk).")
    if "Strict-Transport-Security" not in headers:
        issues.append("Missing HSTS header.")
    if "X-Frame-Options" not in headers:
        issues.append("Missing X-Frame-Options (clickjacking risk).")
    if "X-Content-Type-Options" not in headers:
        issues.append("Missing X-Content-Type-Options (MIME sniffing).")
    if headers.get("Access-Control-Allow-Origin") == "*":
        issues.append("Wildcard CORS policy.")
    return issues

# ---- WAF DETECTION ----
def detect_waf(domain):
    try:
        url = f"http://{domain}/?q=<script>alert(1)</script>"
        r = requests.get(url, timeout=5)
        if r.status_code in [403, 406] or "Access Denied" in r.text:
            return "Possible WAF detected"
        server = r.headers.get("Server", "").lower()
        if any(waf in server for waf in ["cloudflare", "sucuri", "akamai"]):
            return f"Known WAF: {server}"
    except:
        pass
    return "No WAF detected"

# ---- SUBDOMAIN ENUM ----
def subdomain_enum(domain):
    found = []
    lock = threading.Lock()

    def check(sub):
        full = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full)
            with lock:
                found.append(full)
        except:
            pass

    threads = []
    for sub in SUBDOMAINS:
        t = threading.Thread(target=check, args=(sub,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return found

# ---- REPORTS ----
def save_html(report, filename):
    html = f"""<html><head><title>WebPyS Report</title></head><body>
    <h1>WebPyS Report for {report['domain']}</h1>
    <p><strong>IP:</strong> {report['ip']}</p>
    <p><strong>Ports:</strong> {report['ports']}</p>
    <p><strong>HTTP:</strong> {report['http_status']} | <strong>HTTPS:</strong> {report['https_status']}</p>
    <p><strong>WAF:</strong> {report['waf']}</p>
    <h3>Vulnerabilities:</h3><ul>{"".join(f"<li>{v}</li>" for v in report['vulnerabilities'])}</ul>
    <h3>Subdomains:</h3><ul>{"".join(f"<li>{s}</li>" for s in report['subdomains'])}</ul>
    </body></html>"""
    with open(f"{filename}.html", "w", encoding="utf-8") as f:
        f.write(html)

def save_xml(report, filename):
    root = Element("WebPySReport")
    SubElement(root, "Domain").text = report["domain"]
    SubElement(root, "IP").text = report["ip"]
    ports = SubElement(root, "Ports")
    for port, state in report["ports"].items():
        SubElement(ports, f"Port{port}").text = state
    SubElement(root, "HTTPStatus").text = str(report["http_status"])
    SubElement(root, "HTTPSStatus").text = str(report["https_status"])
    SubElement(root, "WAF").text = report.get("waf", "Unknown")
    vulns = SubElement(root, "Vulnerabilities")
    for v in report["vulnerabilities"]:
        SubElement(vulns, "Vuln").text = v
    subs = SubElement(root, "Subdomains")
    for s in report["subdomains"]:
        SubElement(subs, "Subdomain").text = s
    ElementTree(root).write(f"{filename}.xml")

# ---- MAIN ----
def generate_report(domain):
    print_banner()

    if not is_valid_domain(domain):
        console.print("[red][!] Invalid domain[/red]")
        sys.exit(1)

    netloc = urlparse(domain).netloc or urlparse(domain).path
    netloc = netloc.strip().lower()

    ip = resolve_ip(netloc)
    if not ip:
        sys.exit(1)

    print(f"[green][+] Resolved IP: {ip}[/green]")

    report = {
        "domain": netloc,
        "ip": ip,
        "ports": check_ports(netloc)
    }

    if report["ports"].get(443) == "Open":
        report["ssl"] = get_ssl_info(netloc)

    report["http_status"], report["http_headers"] = get_headers(f"http://{netloc}")
    report["https_status"], report["https_headers"] = get_headers(f"https://{netloc}")

    print("[cyan][+] Analyzing vulnerabilities...[/cyan]")
    vulns = []
    if "ssl" in report:
        vulns += analyze_ssl_info(report["ssl"])
    vulns += analyze_http_headers(report["http_headers"])
    vulns += analyze_http_headers(report["https_headers"])
    report["vulnerabilities"] = list(set(vulns))

    print("[cyan][+] Detecting WAF...[/cyan]")
    report["waf"] = detect_waf(netloc)

    print("[cyan][+] Enumerating subdomains...[/cyan]")
    report["subdomains"] = subdomain_enum(netloc)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"webpys_{netloc}_{timestamp}"

    save_html(report, filename)
    save_xml(report, filename)

    print(f"\n[green][+] Reports saved as:[/green] [yellow]{filename}.html[/yellow] and [yellow]{filename}.xml[/yellow]")

if __name__ == "__main__":
    try:
        domain = input("Enter target domain (e.g., example.com): ").strip()
        generate_report(domain)
    except KeyboardInterrupt:
        print("\n[!] Scan aborted.")
