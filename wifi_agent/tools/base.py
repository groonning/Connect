from __future__ import annotations
from dataclasses import dataclass
from ..runner import run, tool_available, RunResult
from ..scope import Scope


@dataclass
class AccessPoint:
    """A network seen during recon."""
    bssid: str
    ssid: str
    channel: str = ""
    encryption: str = ""   # e.g. WPA2, WPA3, WEP, OPN
    power: str = ""        # signal
    wps: bool = False


class ToolWrapper:
    """Base class. Recon (passive scanning) is allowed broadly; any method that
    acts against a specific AP must call self.scope.require(bssid) first.
    """
    binary: str = ""

    def __init__(self, scope: Scope, iface: str = "", dry_run: bool = False):
        self.scope = scope
        self.iface = iface
        self.dry_run = dry_run

    def available(self) -> bool:
        return tool_available(self.binary)

    def _run(self, cmd: list[str], timeout: int | None = None) -> RunResult:
        return run(cmd, timeout=timeout, dry_run=self.dry_run)
