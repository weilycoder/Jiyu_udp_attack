"""
This module provides enhanced command-line interface (CLI) parameter parsing and display.
"""

import argparse

from typing import Any, Iterable, List, Optional, Sequence, cast


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

        super().__init__(_option_strings, dest, **kwargs)

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
            usage = usage % {"prog": self._prog}
        elif usage is None and not actions:
            usage = self._prog
        elif usage is None:
            prog = self._prog

            optionals = []
            positionals = []
            for action in actions:
                if action.option_strings:
                    optionals.append(action)
                else:
                    positionals.append(action)

            format = self._format_actions_usage  # pylint: disable=redefined-builtin
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

        return f"{prefix}{usage}\n\n"

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
            if not group._group_actions:  # pylint: disable=protected-access
                raise ValueError(f"empty group {group}")

            if all(
                action.help is argparse.SUPPRESS for action in group._group_actions  # pylint: disable=protected-access
            ):
                continue

            try:
                start = actions.index(group._group_actions[0])  # pylint: disable=protected-access
            except ValueError:
                continue
            else:
                end = start + len(group._group_actions)  # pylint: disable=protected-access
                if actions[start:end] == group._group_actions:  # pylint: disable=protected-access
                    group_actions.update(group._group_actions)  # pylint: disable=protected-access
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
                    part = f"{option_string} {args_string}"
                if not action.required and action not in group_actions:
                    part = f"[{part}]"

            parts.append(part)

        inserted_separators_indices = set()
        for start, end in sorted(inserts, reverse=True):
            group = inserts[start, end]
            group_parts = [item for item in parts[start:end] if item is not None]
            group_size = len(group_parts)
            if group.required:
                open, close = "()" if group_size > 1 else ("", "")  # pylint: disable=redefined-builtin
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
        if action.nargs == 0:
            return ", ".join(action.option_strings)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(action.option_strings) + " " + args_string

    def _format_args(self, action: argparse.Action, default_metavar: str) -> str:
        get_metavar = self._metavar_formatter(action, default_metavar)
        if action.nargs is None:
            result = f"{get_metavar(1)[0]}"
        elif action.nargs == argparse.OPTIONAL:
            result = f"[{get_metavar(1)[0]}]"
        elif action.nargs == argparse.ZERO_OR_MORE:
            metavar = get_metavar(1)
            if len(metavar) == 2:
                result = f"[{metavar[0]} [{metavar[1]} ...]]"
            else:
                result = f"[{metavar[0]} ...]"
        elif action.nargs == argparse.ONE_OR_MORE:
            metavar = get_metavar(1)
            result = f"{metavar[0]} [{metavar[1]} ...]"
        elif action.nargs == argparse.REMAINDER:
            result = "..."
        elif action.nargs == argparse.PARSER:
            result = f"{get_metavar(1)[0]} ..."
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
