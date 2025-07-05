"""
This module is used to send or broadcast UDP packets with spoofed IP addresses.
"""

import struct
import random
import socket
from typing import List, Optional, Tuple

try:
    from Jiyu_udp_attack.ip_analyze import ip_analyze
except ImportError:
    from ip_analyze import ip_analyze


def calculate_checksum(data: bytes) -> int:
    """
    Calculates the checksum for the given data.

    Args:
        data (bytes): The data for which to calculate the checksum.

    Returns:
        int: The calculated checksum.
    """
    data = data + b"\x00" * (len(data) % 2)  # Ensure even length

    total = 0
    for word in struct.unpack("!" + "H" * (len(data) // 2), data):
        total += word
        if total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF


def create_raw_udp_packet(
    src_ip: str,
    src_port: Optional[int],
    dst_ip: str,
    dst_port: int,
    payload: bytes,
    *,
    ip_id: Optional[int] = None,
) -> bytes:
    """
    Creates a raw UDP packet with a spoofed source IP address.

    Args:
        src_ip (str): The source IP address to spoof.
        dst_ip (str): The destination IP address.
        dst_port (int): The destination port number.
        payload (bytes): The data payload to include in the packet.

    Returns:
        bytes: The constructed raw UDP packet.
    """
    # 1. Set IP header parameters
    ip_ver = 4
    ip_ihl = 5  # 5 * 4 = 20 bytes header
    ip_tos = 0
    ip_total_len = 20 + 8 + len(payload)  # IP header + UDP header + data
    ip_id = random.randint(0, 65535) if ip_id is None else ip_id
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0  # Initial value is 0, will be calculated later

    # 2. Build IP header (initial checksum is 0)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (ip_ver << 4) | ip_ihl,
        ip_tos,
        ip_total_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    # 3. Calculate IP header checksum
    ip_check = calculate_checksum(ip_header)

    # 4. Rebuild IP header with correct checksum
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (ip_ver << 4) | ip_ihl,
        ip_tos,
        ip_total_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    # 5. Build UDP header (initial checksum is 0)
    if src_port is None:
        src_port = random.randint(1024, 65535)  # Random source port
    udp_length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)  # Initial checksum is 0

    # 6. Create pseudo header for UDP checksum calculation
    pseudo_header = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, ip_proto, udp_length)

    # 7. Calculate UDP checksum (including pseudo header)
    udp_check = calculate_checksum(pseudo_header + udp_header + payload)

    # 8. Rebuild UDP header with correct checksum
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_check)

    # 9. Combine complete packet
    return ip_header + udp_header + payload


def send_packet(
    src_ip: Optional[str],
    src_port: Optional[int],
    dst_ip: str,
    dst_port: int,
    payload: bytes,
    *,
    ip_id: Optional[int] = None,
) -> None:
    """
    Sends a UDP packet with a spoofed source IP address.

    Args:
        src_ip (Optional[str]): The source IP address to spoof. If None, spoofing is not performed.
        src_port (Optional[int]): The source port number. If None, a random port will be used.
        dst_ip (str): The destination IP address.
        dst_port (int): The destination port number.
        payload (bytes): The data payload to include in the packet.
        ip_id (Optional[int]): The IP identification number. If None, a random ID will be used.
    """
    if src_ip is None:
        if src_port is not None or ip_id is not None:
            raise ValueError("If src_ip is None, src_port and ip_id must also be None.")
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.sendto(payload, (dst_ip, dst_port))
    else:
        client = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        client.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        packet = create_raw_udp_packet(src_ip, src_port, dst_ip, dst_port, payload, ip_id=ip_id)
        client.sendto(packet, (dst_ip, dst_port))


def broadcast_packet(
    src_ip: str,
    src_port: Optional[int],
    dst_ip: str,
    dst_port: int,
    payload: bytes,
    *,
    ip_id: Optional[int] = None,
) -> List[Tuple[str, int]]:
    """
    Sends a broadcast UDP packet to the specified destination IP address or range.

    This function analyzes the destination IP address or range and sends the packet to each valid IP address.

    Args:
        src_ip (str): The source IP address.
        src_port (Optional[int]): The source port number. If None, a random port will be used.
        dst_ip (str): The broadcast IP address (e.g., "192.168.1.255", "192.168.1.0/24", "192.168.1.10-100").
        dst_port (int): The destination port number.
        payload (bytes): The data payload to include in the packet.
        ip_id (Optional[int]): The IP identification number. If None, a random ID will be used.
        
    Returns:
        List[Tuple[str, int]]: A list of tuples containing the IP addresses and ports to which the packets were sent.
    """
    sent_list: List[Tuple[str, int]] = []
    for ip, port in ip_analyze(dst_ip):
        port = port if 0 <= port <= 0xffff else dst_port
        send_packet(src_ip, src_port, ip, dst_port, payload, ip_id=ip_id)
        sent_list.append((ip, port))
    return sent_list
