"""
This module is used to send or broadcast UDP packets with spoofed IP addresses.
"""

import scapy.all as scapy

from Jiyu_udp_attack.ip_analyze import ip_analyze


def send_packet(src_ip: str, dst_ip: str, dst_port: int, data: bytes) -> None:
    """
    Sends a UDP packet with the specified source IP, destination IP, destination port, and data payload.

    Args:
        src_ip (str): The source IP address.
        dst_ip (str): The destination IP address.
        dst_port (int): The destination port number.
        data (bytes): The data payload to include in the packet.

    Raises:
        scapy.error.Scapy_Exception: If there is an error sending the packet.

    Note:
        This function uses Scapy to construct and send the packet.
        Ensure that Scapy is installed and properly configured in your environment.
    """
    # pylint: disable=no-member
    packet = scapy.IP(src=src_ip, dst=dst_ip) / scapy.UDP(dport=dst_port) / scapy.Raw(load=data)  # type: ignore
    scapy.send(packet, count=1, verbose=False)


def broadcast_packet(src_ip: str, dst_ip: str, dst_port: int, data: bytes) -> None:
    """
    Sends a broadcast UDP packet to the specified destination IP address or range.

    This function analyzes the destination IP address or range and sends the packet to each valid IP address.

    Args:
        src_ip (str): The source IP address.
        dst_ip (str): The broadcast IP address (e.g., "192.168.1.255", "192.168.1.0/24", "192.168.1.10-100").
        dst_port (int): The destination port number.
        data (bytes): The data payload to include in the packet.
    """
    for ip in ip_analyze(dst_ip):
        send_packet(src_ip, ip, dst_port, data)
