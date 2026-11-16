"""Packet analysis of a capture file (tshark, the Wireshark CLI). Read-only."""
from __future__ import annotations
from pathlib import Path
from .base import ToolWrapper


class Tshark(ToolWrapper):
    binary = "tshark"

    def summary(self, pcap_file: str, display_filter: str = "", timeout: int = 120):
        if not Path(pcap_file).exists():
            raise FileNotFoundError(pcap_file)
        cmd = [self.binary, "-r", pcap_file]
        if display_filter:
            cmd += ["-Y", display_filter]
        return self._run(cmd, timeout=timeout)
