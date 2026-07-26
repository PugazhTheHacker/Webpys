"""Vulnerability scanner: basic SQLi and XSS detection plus helpers"""
import requests
from urllib.parse import urljoin

SQL_PAYLOADS = ["' OR '1'='1' -- ", '" OR "1"="1" -- ', "' OR 1=1 -- "]
XSS_PAYLOADS = ['<script>alert(1)</script>', '"><svg/onload=alert(1)>']
ERROR_SIGNATURES = ['sql syntax', 'mysql', 'unknown column', 'syntax error', 'unterminated string']


def check_robots(target):
    base = target if target.startswith('http') else f'https://{target}'
    try:
        r = requests.get(base.rstrip('/') + '/robots.txt', timeout=3)
        return {'exists': r.status_code == 200, 'status': r.status_code, 'body': r.text[:200]}
    except Exception:
        return {'exists': False}


def _evidence_from_text(text):
    if not text:
        return None
    tl = text.lower()
    for sig in ERROR_SIGNATURES:
        if sig in tl:
            return f'Error signature: {sig}'
    return None


def _test_sql_injection(url, timeout=5):
    findings = []
    for p in SQL_PAYLOADS:
        try:
            r = requests.get(url, params={'q': p}, timeout=timeout, allow_redirects=True)
            # Look for error signatures
            ev = _evidence_from_text(r.text)
            if ev:
                findings.append({'type': 'sql_injection', 'payload': p, 'url': r.url, 'evidence': ev, 'status': r.status_code})
            else:
                # boolean heuristic: different content length or status
                if r.status_code == 200 and len(r.text) > 0 and p in r.text:
                    findings.append({'type': 'sql_injection', 'payload': p, 'url': r.url, 'evidence': 'payload reflected', 'status': r.status_code})
        except Exception:
            continue
    return findings


def _test_xss(url, timeout=5):
    findings = []
    for p in XSS_PAYLOADS:
        try:
            r = requests.get(url, params={'q': p}, timeout=timeout, allow_redirects=True)
            if p in r.text:
                findings.append({'type': 'xss', 'payload': p, 'url': r.url, 'evidence': 'payload reflected', 'status': r.status_code})
        except Exception:
            continue
    return findings


def scan_vulnerabilities(target, paths, timeout=5):
    """Scan target and discovered paths for basic SQLi/XSS by testing common payloads.
    paths: list of dicts with 'url' or strings; function normalizes.
    Returns list of findings.
    """
    findings = []
    base = target if target.startswith('http') else f'https://{target}'

    # Ensure we test the root as well
    candidates = set()
    candidates.add(base.rstrip('/') + '/')

    for p in paths or []:
        if isinstance(p, dict) and 'url' in p:
            candidates.add(p['url'])
        elif isinstance(p, str):
            candidates.add(urljoin(base, p))

    for url in list(candidates):
        # try SQLi
        sres = _test_sql_injection(url, timeout=timeout)
        if sres:
            findings.extend(sres)
        # try XSS
        xres = _test_xss(url, timeout=timeout)
        if xres:
            findings.extend(xres)

    return findings


def basic_checks(target):
    checks = {}
    checks['robots'] = check_robots(target)
    return checks
