"""Find subdomains by wordlist (simple DNS resolve)"""
import socket
from concurrent.futures import ThreadPoolExecutor


def _try_resolve(name):
    try:
        ip = socket.gethostbyname(name)
        return {'name': name, 'ip': ip}
    except Exception:
        return None


def find_subdomains(domain, wordlist_path='wordlists/subdomains.txt', threads=30):
    results = []
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            words = [w.strip() for w in f if w.strip()]
    except FileNotFoundError:
        words = ['www','dev','test','api','staging','mail','ftp']

    candidates = [f"{w}.{domain}" for w in words]
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(_try_resolve, candidates):
            if r:
                results.append(r)
    return results
