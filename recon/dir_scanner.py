"""Directory brute-force using HTTP status checks"""
import requests


def scan_dirs(target, wordlist_path='wordlists/dirs.txt', timeout=3, threads=10):
    base = target if target.startswith('http') else f'https://{target}'
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            paths = [p.strip() for p in f if p.strip()]
    except FileNotFoundError:
        paths = ['admin','login','robots.txt','.env','uploads']

    found = []
    for p in paths:
        url = base.rstrip('/') + '/' + p.lstrip('/')
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code != 404:
                found.append({'path': p, 'url': url, 'status': r.status_code})
        except requests.RequestException:
            continue
    return found
