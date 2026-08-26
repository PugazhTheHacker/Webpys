
      
# WebPyX Scan v3.0.1 (CyberScan)
**Author**: pugazhenthi J

> A Python-based Reconnaissance and Security Scanning Toolkit for authorized security testing, learning, and research.


## Overview

**WebPyX Scan v3.0.1** is a modular reconnaissance framework written in Python. It combines common reconnaissance techniques into a single command-line application capable of discovering subdomains, scanning TCP ports, performing directory enumeration, and generating detailed reports in JSON and HTML formats.

 The project is designed with a modular architecture, allowing new scanning modules to be added with minimal changes.

> **Note:** This project is intended only for authorized penetration testing, security assessments, education, and research.


# Features

## Subdomain Discovery

- DNS-based subdomain enumeration
- Custom wordlist support
- Multi-threaded resolution
- Returns discovered hostname and IP address

---

## Port Scanner

- High-speed asynchronous TCP connect scanner
- Supports:
  - Single ports
  - Multiple ports
  - Port ranges
- Configurable timeout
- Concurrent scanning

Example:

```
22
80
443
22,80,443
8000-8100
22,80,443,8000-8010
```

---

## Directory Discovery

- HTTP directory/path brute forcing
- Custom directory wordlists
- HTTP status detection
- Threaded requests

Example discoveries:

```
/admin
/login
/dashboard
/api
/uploads
```

---

## Report Generator

Automatically generates:

- JSON report
- HTML report

Useful for:

- Documentation
- Security assessment reports
- Further automation

---

## Vulnerability Helper Module

The project includes a standalone vulnerability scanner located at:

```
scanners/vuln_scanner.py
```

Current capabilities:

- robots.txt check
- Basic SQL Injection heuristics
- Basic reflected XSS heuristics

**Note**

This module currently exists independently and is **not yet integrated** into the main scanning workflow.

---

# Project Structure

```text
cyberscan/
│
├── assets/
│   └── banner
│
├── main.py
│
├── recon/
│   ├── subdomain_scanner.py
│   └── dir_scanner.py
│
├── scanners/
│   ├── port_scanner.py
│   └── vuln_scanner.py
│
├── reports/
│   └── reporter.py
│
├── wordlists/
│   ├── subdomains.txt
│   └── dirs.txt
│
├── requirements.txt
│
└── my_library_project/
```

---

# Requirements

Python **3.10+** recommended.

Required packages:

```
requests
aiohttp
dnspython
python-nmap
tqdm
colorama
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/yourusername/webpys.git
cd webpys
```

Create a virtual environment

### Windows

```bash
python -m venv .venv

.venv\Scripts\activate
```

### Linux

```bash
python3 -m venv .venv

source .venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Command Line Usage

Basic syntax

```bash
python main.py --target example.com --all
```

Generate reports

```bash
python main.py --target example.com --all --output reports/result
```

---

# Available Arguments

| Argument | Description |
|-----------|-------------|
| `--target` | Target domain or IP address |
| `--ports` | Port list or ranges |
| `--subdomains` | Custom subdomain wordlist |
| `--dirs` | Custom directory wordlist |
| `--output` | Report output path |
| `--all` | Run all scan modules |

---

# Examples

## Full Scan

```bash
python main.py --target scanme.nmap.org --all --output reports/scanme_full
```

---

## Port Scan Only

```bash
python main.py --target 192.168.1.1 --ports 22,80,443,8080-8090
```

---

## Custom Subdomain Wordlist

```bash
python main.py --target example.com --subdomains wordlists/subdomains.txt
```

---

## Custom Directory Wordlist

```bash
python main.py --target example.com --dirs wordlists/dirs.txt
```

---

# Scan Workflow

When the application starts:

```
                +------------------+
                |  Target Input    |
                +---------+--------+
                          |
                          v
              Validate Target
                          |
          +---------------+---------------+
          |                               |
          v                               v
 Subdomain Scanner                Port Scanner
          |                               |
          +---------------+---------------+
                          |
                          v
                 Directory Scanner
                          |
                          v
                 Report Generator
                          |
                          v
            JSON Report + HTML Report
```

---

# Output

Using

```bash
--output reports/result
```

creates

```
reports/result.json

reports/result.html
```

---

Example JSON

```json
{
  "findings": {
    "subdomains": [],
    "open_ports": [],
    "found_paths": []
  }
}
```

---

# Module Documentation

## recon/subdomain_scanner.py

Function

```python
find_subdomains(
    domain,
    wordlist_path="wordlists/subdomains.txt",
    threads=30
)
```

Returns

```python
[
    {
        "name":"api.example.com",
        "ip":"93.184.216.34"
    }
]
```

---

## recon/dir_scanner.py

Function

```python
scan_dirs(
    target,
    wordlist_path="wordlists/dirs.txt",
    timeout=3,
    threads=10
)
```

Returns

```python
[
    {
        "path":"admin",
        "url":"https://example.com/admin",
        "status":200
    }
]
```

---

## scanners/port_scanner.py

Function

```python
scan_ports(
    host,
    ports,
    timeout=1.0,
    concurrency=200
)
```

Returns

```python
[22,80,443]
```

---

## reports/reporter.py

```python
Reporter(out_prefix="reports/result")
```

Methods

```python
add(key,value)

save()
```

Output

- JSON
- HTML

---

## scanners/vuln_scanner.py

Functions

```python
basic_checks(target)

scan_vulnerabilities(
    target,
    paths,
    timeout=5
)
```

Capabilities

- robots.txt check
- SQL Injection heuristics
- XSS reflection heuristics

---

# Reusable Validation Library

The repository includes a reusable validation package.

```
my_library_project/
```

Provides

- URL normalization
- Host validation
- Domain/IP validation
- Host extraction
- Port parsing
- Port range parsing

---

## Installation

```bash
cd my_library_project

pip install -e .
```

---

## Example

```python
from my_library import TargetValidator

validator = TargetValidator()

result = validator.validate("example.com")

print(result.valid)

print(result.normalized_target)
```

---

# Running Tests

```
bash
cd my_library_project

set PYTHONPATH=src

python -m unittest discover -s tests -v
```

---

# Future Roadmap

- Full vulnerability scanner integration
- Banner grabbing
- HTTP header analysis
- SSL certificate analysis
- Technology fingerprinting
- WHOIS lookup
- DNS enumeration
- WAF detection
- Screenshot capture
- Service detection
- CVE lookup
- Export to PDF
- Multi-target scanning
- Plugin architecture
- Docker support

---

# Legal Notice

This software is intended **only** for systems that you own or have explicit written permission to assess.

Unauthorized scanning or testing of third-party systems may violate laws, regulations, or terms of service. The author and contributors are **not responsible** for any misuse of this software.

---

# Author

**Pugazhenthi J**

Cybersecurity Enthusiast • Ethical Hacker • Penetration Tester

---

# Version

**WebPyS Scan v3.0.1**

---

# License

MIT License

---

## Support

If you find this project useful, consider giving it a ⭐ on GitHub and contributing through pull requests or issue reports.

Happy Recon! 🚀
````
```
   cd ./webpys
```

# create & activate venv (Linux / macOS)


```
python3 -m venv venv
```


```
source venv/bin/activate
```
# or on Windows (PowerShell)
```
python -m venv venv
```
```
.\venv\Scripts\Activate.ps1
``` 
#stall dependencies

 ```
pip install --upgrade pip
```

```
pip install -r requirements.txt
```

```  
  python webpys.py
  ```





 
