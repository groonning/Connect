"""Tool preflight — everything the agent needs is checked (and the scanner
auto-started) when the server boots, so the operator sees one status strip.
"""
from __future__ import annotations
from .runner import tool_available

# Programs the agent drives. name -> (apt package, what it's for)
REQUIRED = {
    "airodump-ng": ("aircrack-ng", "scan + capture"),
    "aireplay-ng": ("aircrack-ng", "deauth (needs injection)"),
    "aircrack-ng": ("aircrack-ng", "crack handshake"),
    "tshark":      ("tshark", "traffic inspection + decryption"),
    "nmap":        ("nmap", "device weakness scan"),
    "hcxpcapngtool": ("hcxtools", "PMKID extraction"),
}


def check() -> list[dict]:
    out = []
    for binary, (pkg, use) in REQUIRED.items():
        out.append({"tool": binary, "package": pkg, "use": use,
                    "ok": tool_available(binary)})
    return out


def missing() -> list[str]:
    return [c["tool"] for c in check() if not c["ok"]]
