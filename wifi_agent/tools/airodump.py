"""Recon: discover nearby access points (airodump-ng, part of aircrack-ng).

Scanning the airwaves is passive, so it is not gated by scope. Scope is enforced
later, when you target a specific AP for capture/cracking.
"""
from __future__ import annotations
import csv
import glob
import os
import tempfile
from .base import ToolWrapper, AccessPoint


class Airodump(ToolWrapper):
    binary = "airodump-ng"

    def scan(self, seconds: int = 20) -> list[AccessPoint]:
        """Sweep for APs and return what was seen. Requires monitor-mode iface."""
        prefix = os.path.join(tempfile.mkdtemp(prefix="airodump_"), "scan")
        cmd = [self.binary, "--write", prefix, "--output-format", "csv",
               "--write-interval", "1", self.iface]
        # airodump runs until killed; the CLI layer is expected to time-box it.
        self._run(cmd, timeout=seconds)
        return self._parse_latest(prefix)

    @staticmethod
    def _parse_latest(prefix: str) -> list[AccessPoint]:
        files = sorted(glob.glob(prefix + "*.csv"))
        if not files:
            return []
        aps: list[AccessPoint] = []
        with open(files[-1], newline="", errors="ignore") as fh:
            for row in csv.reader(fh):
                if not row or len(row) < 14:
                    continue
                bssid = row[0].strip()
                if bssid == "BSSID" or ":" not in bssid:
                    continue  # header or the client section
                aps.append(AccessPoint(
                    bssid=bssid,
                    ssid=row[13].strip(),
                    channel=row[3].strip(),
                    encryption=row[5].strip(),
                    power=row[8].strip(),
                ))
        return aps
