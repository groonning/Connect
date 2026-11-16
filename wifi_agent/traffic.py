"""Live traffic inspection via tshark, over the rolling capture file.

If the agent has cracked a PSK for an authorised network, that key is passed to
tshark so the network's own traffic is decrypted. Each packet is tagged:
  - protected=0 + has IP  -> cleartext (visible without any key)
  - protected=1 + has IP  -> decrypted by the agent (key applied)
  - protected=1, no IP    -> still encrypted (no key / not this network)
Also builds a MAC->IP map so the device panels can line up a station with its
address on the network.
"""
from __future__ import annotations
import os
import subprocess

FIELDS = ["frame.time_relative", "wlan.sa", "wlan.da", "ip.src", "ip.dst",
          "_ws.col.Protocol", "_ws.col.Info", "wlan.fc.protected"]


class TrafficInspector:
    def __init__(self, keys: list[tuple[str, str]] | None = None):
        # keys: list of (psk, ssid) for authorised, cracked networks
        self.keys = keys or []

    def _cmd(self, cap: str, limit: int) -> list[str]:
        cmd = ["tshark", "-r", cap, "-T", "fields"]
        for f in FIELDS:
            cmd += ["-e", f]
        cmd += ["-E", "separator=\t", "-E", "occurrence=f"]
        if self.keys:
            cmd += ["-o", "wlan.enable_decryption:TRUE"]
            uat = ",".join(f'"wpa-pwd","{psk}:{ssid}"' for psk, ssid in self.keys)
            # one -o per key is the robust form:
            cmd = ["tshark", "-r", cap, "-o", "wlan.enable_decryption:TRUE"]
            for psk, ssid in self.keys:
                cmd += ["-o", f'uat:80211_keys:"wpa-pwd","{psk}:{ssid}"']
            cmd += ["-T", "fields"]
            for f in FIELDS:
                cmd += ["-e", f]
            cmd += ["-E", "separator=\t", "-E", "occurrence=f"]
        cmd += ["-c", str(limit)]
        return cmd

    def read(self, cap: str, limit: int = 300, only: str = "all",
             device: str = "", proto: str = "") -> dict:
        """only: all|cleartext|decrypted ; device: filter by MAC ; proto: substring."""
        if not cap or not os.path.exists(cap):
            return {"packets": [], "mac_ip": {}}
        try:
            res = subprocess.run(self._cmd(cap, limit * 4), capture_output=True,
                                 text=True, timeout=30)
        except Exception as e:
            return {"packets": [], "mac_ip": {}, "error": str(e)}
        packets, mac_ip = [], {}
        for line in res.stdout.splitlines():
            parts = (line.split("\t") + [""] * 8)[:8]
            t, sa, da, src, dst, pr, info, prot = parts
            protected = prot.strip() in ("1", "True")
            has_ip = bool(src or dst)
            if protected and has_ip:
                state = "decrypted"
            elif not protected and has_ip:
                state = "cleartext"
            elif not protected and not has_ip and pr:
                state = "cleartext"       # mgmt/control frames, ARP, etc.
            else:
                state = "encrypted"
            if sa and src:
                mac_ip[sa.upper()] = src
            rec = {"time": t, "sa": sa, "da": da, "src": src, "dst": dst,
                   "proto": pr, "info": info[:140], "state": state}
            if only != "all" and state != only:
                continue
            if device and device.upper() not in (sa.upper(), da.upper()):
                continue
            if proto and proto.lower() not in pr.lower():
                continue
            packets.append(rec)
            if len(packets) >= limit:
                break
        return {"packets": packets, "mac_ip": mac_ip}
