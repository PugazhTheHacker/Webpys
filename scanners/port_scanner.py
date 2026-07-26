"""Async TCP port scanner (simple)"""
import asyncio
import socket
from functools import partial

async def _scan_port(host, port, timeout=1.0, sem=None):
    if sem: await sem.acquire()
    loop = asyncio.get_event_loop()
    try:
        fut = loop.run_in_executor(None, partial(_tcp_connect, host, port, timeout))
        ok = await asyncio.wait_for(fut, timeout+0.5)
        return port if ok else None
    except Exception:
        return None
    finally:
        if sem: sem.release()


def _tcp_connect(host, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        s.close()
        return True
    except Exception:
        return False


def scan_ports(host, ports, timeout=1.0, concurrency=200):
    """Scan a list of ports on host. Returns list of open ports."""
    async def runner():
        sem = asyncio.Semaphore(concurrency)
        tasks = [asyncio.create_task(_scan_port(host, p, timeout, sem)) for p in ports]
        res = await asyncio.gather(*tasks)
        return [p for p in res if p]

    try:
        return asyncio.run(runner())
    except RuntimeError:
        # If event loop already running (embedded), fallback
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(runner())
