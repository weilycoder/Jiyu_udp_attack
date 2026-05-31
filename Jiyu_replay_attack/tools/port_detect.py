"""
Local UDP listener detection helpers.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

import psutil


def list_udp_listeners(
    process_keywords: Optional[Sequence[str]] = None,
) -> List[Tuple[str, int, Optional[int], Optional[str]]]:
    """
    Return local UDP listeners with optional process keyword filtering.
    """
    if isinstance(process_keywords, str):
        process_keywords = [process_keywords]
    keywords = [k.lower() for k in process_keywords] if process_keywords else None
    results: List[Tuple[str, int, Optional[int], Optional[str]]] = []
    seen = set()

    for conn in psutil.net_connections(kind="udp"):
        if not conn.laddr:
            continue
        ip = conn.laddr.ip
        port = conn.laddr.port
        pid = conn.pid
        name: Optional[str] = None

        if pid is not None:
            try:
                name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                name = None

        if keywords and (not name or not any(k in name.lower() for k in keywords)):
            continue

        key = (ip, port, pid)
        if key in seen:
            continue
        seen.add(key)

        results.append((ip, port, pid, name))

    return results


def candidate_udp_ports(process_keywords: Optional[Sequence[str]] = None) -> List[int]:
    """
    Return sorted UDP ports from local listeners, optionally filtered by process keywords.
    """
    ports = {item[1] for item in list_udp_listeners(process_keywords)}
    return sorted(ports)
