"""
This module is used to send or broadcast UDP packets with spoofed IP addresses.
"""

import socket
from typing import List, Optional, Tuple

from scapy.all import send as scapy_send
from scapy.all import IP, UDP, Raw, RandShort  # pylint: disable=no-name-in-module  # type: ignore

try:
    from Jiyu_udp_attack.ip_analyze import ip_analyze
except ImportError:
    from ip_analyze import ip_analyze


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
        ip_layer = IP(src=src_ip, dst=dst_ip)
        udp_layer = UDP(sport=RandShort() if src_port is None else src_port, dport=dst_port)
        packet = ip_layer / udp_layer / Raw(load=payload)
        scapy_send(packet, verbose=0)


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
