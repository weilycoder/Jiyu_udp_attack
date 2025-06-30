"""
This module provides functions to analyze IP addresses and ranges, converting them into a list of valid IP addresses.
"""


from typing import List, Tuple


def ip_to_tuple(ip: str) -> Tuple[int, int, int, int]:
    """
    Converts an IP address string to a tuple of four integers.

    Args:
        ip (str): The IP address in string format (e.g., "192.168.1.1").

    Returns:
        tuple[int, int, int, int]: A tuple representing the four octets of the IP address.
    """
    if not isinstance(ip, str):
        raise TypeError(f"Expected string, got {type(ip).__name__}")
    try:
        ip_tuple = tuple(int(x) for x in ip.split("."))
    except ValueError:
        raise ValueError(f"Invalid IP address format: {ip}") from None
    if len(ip_tuple) != 4 or any(x < 0 or x > 255 for x in ip_tuple):
        raise ValueError(f"Invalid IP address format: {ip}")
    return ip_tuple


# pylint: disable=too-many-branches
def ip_analyze(ip: str) -> List[str]:
    """
    Analyzes an IP address or range and returns a list of valid IP addresses.

    Args:
        ip (str): The IP address or range in string format (e.g., "192.168.1.1", "192.168.1.1/24", "192.168.1.1-100").

    Returns:
        list[str]: A list of valid IP addresses.
    """
    if not isinstance(ip, str):
        raise TypeError(f"Expected string, got {type(ip).__name__}")
    ip = ip.replace(" ", "")
    if "/" in ip:
        try:
            ip_addr, mask = ip.split("/")
            assert mask.isdigit(), f"Invalid subnet mask: {mask}"
            mask = int(mask)
            assert mask in range(0, 32, 8), f"Invalid subnet mask: {mask}"
        except ValueError:
            raise ValueError(f"Invalid IP address format: {ip}") from None
        except AssertionError as e:
            raise ValueError(str(e)) from None
        ip_tuple = ip_to_tuple(ip_addr)
        ip32 = ip_tuple[0] << 24 | ip_tuple[1] << 16 | ip_tuple[2] << 8 | ip_tuple[3]
        ip32 |= (1 << (32 - mask)) - 1
        return [f"{(ip32 >> 24) & 0xFF}.{(ip32 >> 16) & 0xFF}.{(ip32 >> 8) & 0xFF}.{ip32 & 0xFF}"]
    if "-" in ip:
        ip_range_tuple = ip.split(".")
        if len(ip_range_tuple) != 4:
            raise ValueError(f"Invalid IP address range format: {ip}")
        ip_count = 1
        ip_range: list[tuple[int, int]] = []
        for i in ip_range_tuple:
            rg = i.split("-")
            if len(rg) ==1:
                rg.append(rg[0])
            if len(rg) != 2:
                raise ValueError(f"Invalid IP address range format: {ip}")
            if not all(x.isdigit() for x in rg):
                raise ValueError(f"Invalid IP address range format: {ip}")
            start, end = int(rg[0]), int(rg[1])
            if start < 0 or start > 255 or end < 0 or end > 255 or start > end:
                raise ValueError(f"Invalid IP address range: {start}-{end}")
            ip_range.append((start, end))
            ip_count *= ip_range[-1][1] - ip_range[-1][0] + 1
        if ip_count > 65536:
            raise ValueError(f"IP address range too large: {ip_count} addresses")
        return [
            f"{a}.{b}.{c}.{d}"
            for a in range(ip_range[0][0], ip_range[0][1] + 1)
            for b in range(ip_range[1][0], ip_range[1][1] + 1)
            for c in range(ip_range[2][0], ip_range[2][1] + 1)
            for d in range(ip_range[3][0], ip_range[3][1] + 1)
        ]
    ip_tuple = ip_to_tuple(ip)
    return [f"{ip_tuple[0]}.{ip_tuple[1]}.{ip_tuple[2]}.{ip_tuple[3]}"]
