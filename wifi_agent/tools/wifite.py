"""Handshake capture against an AUTHORISED target, via wifite2.

wifite is an orchestrator itself; here we constrain it to a single BSSID that has
passed the scope gate, so it can't wander onto neighbouring networks.
"""
from __future__ import annotations
from .base import ToolWrapper


class Wifite(ToolWrapper):
    binary = "wifite"

    def capture_handshake(self, bssid: str, channel: str = "", timeout: int = 300):
        target = self.scope.require(bssid)   # <-- hard authorisation gate
        cmd = [self.binary, "--bssid", target.bssid, "--no-wps",
               "--kill"]  # --kill frees the interface from NetworkManager
        if channel:
            cmd += ["-c", channel]
        return self._run(cmd, timeout=timeout)
