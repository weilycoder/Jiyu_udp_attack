"""
This module provides functions to analyze IP addresses and ranges, converting them into a list of valid IP addresses.
"""


def ip_to_tuple(ip: str) -> tuple[int, int, int, int]:
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
def ip_analyze(ip: str) -> list[str]:
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
        match ip.split("/"):
            case [ip_addr, mask]:
                if not mask.isdigit():
                    raise ValueError(f"Invalid subnet mask: {mask}")
                mask = int(mask)
                if mask < 0 or mask > 32:
                    raise ValueError(f"Subnet mask out of range: {mask}")
                if mask < 16:
                    raise ValueError(f"Subnet mask too small: {mask}")
            case _:
                raise ValueError(f"Invalid IP address format: {ip}")
        ip_tuple = ip_to_tuple(ip_addr)
        ip32 = ip_tuple[0] << 24 | ip_tuple[1] << 16 | ip_tuple[2] << 8 | ip_tuple[3]
        ip32 &= (0xFFFFFFFF >> (32 - mask)) << (32 - mask)
        return [
            f"{(i >> 24) & 0xFF}.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"
            for i in range(ip32 + 1, ip32 | ((1 << (32 - mask)) - 1))
        ]
    if "-" in ip:
        ip_range_tuple = ip.split(".")
        if len(ip_range_tuple) != 4:
            raise ValueError(f"Invalid IP address range format: {ip}")
        ip_count = 1
        ip_range: list[tuple[int, int]] = []
        for i in ip_range_tuple:
            match i.split("-"):
                case [single]:
                    if not single.isdigit():
                        raise ValueError(f"Invalid IP address range format: {ip}")
                    single = int(single)
                    if single < 0 or single > 255:
                        raise ValueError(f"IP address out of range: {single}")
                    ip_range.append((single, single))
                case [start, end]:
                    if not (start.isdigit() and end.isdigit()):
                        raise ValueError(f"Invalid IP address range format: {ip}")
                    start = int(start)
                    end = int(end)
                    if start < 0 or start > 255 or end < 0 or end > 255 or start > end:
                        raise ValueError(f"Invalid IP address range: {start}-{end}")
                    ip_range.append((start, end))
                case _:
                    raise ValueError(f"Invalid IP address range format: {ip}")
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
