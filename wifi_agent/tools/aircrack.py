"""Offline cracking of a captured handshake against a wordlist (aircrack-ng).

Works on a .cap file you already captured from an authorised target. Scope is
re-checked on the BSSID the capture belongs to.
"""
from __future__ import annotations
from pathlib import Path
from .base import ToolWrapper


class Aircrack(ToolWrapper):
    binary = "aircrack-ng"

    def crack(self, cap_file: str, bssid: str, wordlist: str, timeout: int | None = None):
        self.scope.require(bssid)            # <-- hard authorisation gate
        if not Path(cap_file).exists():
            raise FileNotFoundError(cap_file)
        if not Path(wordlist).exists():
            raise FileNotFoundError(f"wordlist not found: {wordlist}")
        cmd = [self.binary, "-b", bssid, "-w", wordlist, cap_file]
        return self._run(cmd, timeout=timeout)
