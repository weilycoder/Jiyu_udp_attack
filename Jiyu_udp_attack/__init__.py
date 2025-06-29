"""
This module is used to forge Jiyu's UDP packets and send them to the student client.
"""

try:
    from Jiyu_udp_attack.sender import send_packet, broadcast_packet
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
except ImportError:
    from sender import send_packet, broadcast_packet
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


__all__ = [
    "send_packet",
    "broadcast_packet",
    "pkg_close_top_window",
    "pkg_close_windows",
    "pkg_message",
    "pkg_shutdown",
    "pkg_rename",
    "pkg_website",
    "pkg_execute",
    "pkg_customize",
]
