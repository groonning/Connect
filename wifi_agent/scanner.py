"""Live recon: run airodump-ng in the background, parse its CSV for both access
points and connected clients (stations). Passive — not scope-gated.
"""
from __future__ import annotations
import csv
import glob
import os
import signal
import subprocess
import tempfile
from .runner import tool_available
import time
from dataclasses import dataclass, field, asdict


@dataclass
class AP:
    bssid: str
    ssid: str
    channel: str = ""
    encryption: str = ""
    power: str = ""
    wps: bool = False
    clients: int = 0

    def dict(self):
        return asdict(self)


@dataclass
class Client:
    mac: str
    bssid: str          # the AP it is associated with ("(not associated)" if none)
    power: str = ""
    packets: str = ""
    first_seen: str = ""
    last_seen: str = ""

    def dict(self):
        return asdict(self)


class LiveScanner:
    """Starts/stops a long-running airodump-ng and reads its rolling CSV."""

    def __init__(self, iface: str, out_dir: str = "captures"):
        self.iface = iface
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self._proc: subprocess.Popen | None = None
        self._prefix: str | None = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> None:
        if self.running:
            return
        if not tool_available("airodump-ng"):
            return
        self._prefix = os.path.join(
            tempfile.mkdtemp(prefix="scan_", dir=self.out_dir), "live")
        cmd = ["airodump-ng", "--write", self._prefix,
               "--output-format", "pcap,csv", "--write-interval", "1", self.iface]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def _latest_csv(self) -> str | None:
        if not self._prefix:
            return None
        files = sorted(glob.glob(self._prefix + "*.csv"),
                       key=os.path.getmtime, reverse=True)
        return files[0] if files else None

    def latest_cap(self) -> str | None:
        import glob as _g
        if not self._prefix:
            return None
        caps = sorted(_g.glob(self._prefix + "*.cap"),
                      key=os.path.getmtime, reverse=True)
        return caps[0] if caps else None

    def read(self) -> dict:
        """Return {'aps': [...], 'clients': [...]} from the latest CSV."""
        path = self._latest_csv()
        if not path:
            return {"aps": [], "clients": [], "running": self.running}
        aps, clients = self._parse(path)
        counts: dict[str, int] = {}
        for c in clients:
            if c.bssid and c.bssid != "(not associated)":
                counts[c.bssid.upper()] = counts.get(c.bssid.upper(), 0) + 1
        for ap in aps:
            ap.clients = counts.get(ap.bssid.upper(), 0)
        return {"aps": [a.dict() for a in aps],
                "clients": [c.dict() for c in clients],
                "running": self.running}

    @staticmethod
    def _parse(path: str) -> tuple[list[AP], list[Client]]:
        aps: list[AP] = []
        clients: list[Client] = []
        section = "ap"
        with open(path, newline="", errors="ignore") as fh:
            for row in csv.reader(fh):
                if not row or not row[0].strip():
                    continue
                head = row[0].strip()
                if head == "BSSID":
                    section = "ap"; continue
                if head == "Station MAC":
                    section = "client"; continue
                if section == "ap" and len(row) >= 14 and ":" in head:
                    aps.append(AP(
                        bssid=head, ssid=row[13].strip(), channel=row[3].strip(),
                        encryption=(row[5].strip() + " " + row[6].strip()).strip(),
                        power=row[8].strip()))
                elif section == "client" and len(row) >= 6 and ":" in head:
                    clients.append(Client(
                        mac=head, bssid=row[5].strip(), power=row[3].strip(),
                        packets=row[4].strip(), first_seen=row[1].strip(),
                        last_seen=row[2].strip()))
        return aps, clients
