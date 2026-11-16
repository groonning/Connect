"""Per-device weakness assessment.

Passive checks need no network access and no scope gate (you are only observing
what the device already broadcasts). Active scanning (nmap against the device's
IP) is gated on the authorised BSSID the device is associated with.
"""
from __future__ import annotations
import re
import subprocess
from dataclasses import dataclass, field, asdict
from .scope import Scope

# risky services -> (severity, note)
_RISKY = {
    21: ("high", "FTP — often plaintext creds"),
    23: ("high", "Telnet — plaintext, should be off"),
    445: ("high", "SMB — common lateral-movement target"),
    3389: ("medium", "RDP exposed"),
    5900: ("medium", "VNC exposed"),
    1900: ("low", "UPnP/SSDP — info leak"),
    80: ("low", "HTTP admin — no TLS"),
}
_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", re.M)
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
_SCRIPT_RE = re.compile(r"^\|_?\s*([a-z0-9][a-z0-9\-]+):\s*$")


@dataclass
class DeviceFinding:
    mac: str
    ip: str
    severity: str
    title: str
    detail: str = ""

    def dict(self):
        return asdict(self)


class DeviceAudit:
    def __init__(self, scope: Scope):
        self.scope = scope

    def passive(self, mac: str, ap_encryption: str, probes: str = "") -> list[DeviceFinding]:
        f: list[DeviceFinding] = []
        enc = (ap_encryption or "").upper()
        if "OPN" in enc or enc == "":
            f.append(DeviceFinding(mac, "", "high", "On an open network",
                                   "All of this device's traffic is in the clear."))
        elif "WEP" in enc:
            f.append(DeviceFinding(mac, "", "high", "On a WEP network",
                                   "Encryption is broken; traffic is recoverable."))
        if probes.strip():
            f.append(DeviceFinding(mac, "", "low", "Leaks known network names",
                                   f"Probe requests reveal: {probes[:80]}"))
        if not f:
            f.append(DeviceFinding(mac, "", "info", "No passive weakness seen",
                                   "Run an active scan once its IP is known."))
        return f

    def active_scan(self, mac: str, ip: str, bssid: str) -> list[DeviceFinding]:
        self.scope.require(bssid)            # <-- hard gate: authorised net only
        if not ip:
            return [DeviceFinding(mac, "", "info", "Mangler IP",
                                  "Trenger dekryptert ARP/DHCP for å finne adressen.")]
        try:
            # -sV version detection + --script vuln: DETECTS known vulnerabilities
            # (reports them). It does not exploit or gain access.
            out = subprocess.run(["nmap", "-sV", "--script", "vuln", "-T4", ip],
                                 capture_output=True, text=True, timeout=600).stdout
        except Exception as e:
            return [DeviceFinding(mac, ip, "info", "Skanning feilet", str(e))]
        findings: list[DeviceFinding] = []
        # open ports + versions
        for m in _PORT_RE.finditer(out):
            port, svc, ver = int(m.group(1)), m.group(2), m.group(3).strip()
            sev, note = _RISKY.get(port, ("info", f"{svc} åpen"))
            findings.append(DeviceFinding(mac, ip, sev,
                            f"Port {port} åpen ({svc})",
                            note + (f" — {ver}" if ver else "")))
        # real vulnerabilities flagged by the NSE vuln scripts
        findings += self._parse_vulns(out, mac, ip)
        if not findings:
            findings.append(DeviceFinding(mac, ip, "info", "Ingen åpne porter", ""))
        return findings

    @staticmethod
    def _parse_vulns(out: str, mac: str, ip: str) -> list["DeviceFinding"]:
        findings, script, cves, vuln, title = [], None, [], False, ""
        def flush():
            if script and vuln:
                sev = "high" if cves else "medium"
                detail = (title or "").strip()
                if cves:
                    detail = (detail + "  " if detail else "") + ", ".join(sorted(set(cves)))
                findings.append(DeviceFinding(mac, ip, sev,
                                f"Sårbar: {script}", detail[:200]))
        for line in out.splitlines():
            m = _SCRIPT_RE.match(line.rstrip())
            if m:
                flush(); script, cves, vuln, title = m.group(1), [], False, ""
                continue
            cves += _CVE_RE.findall(line)
            if "VULNERABLE" in line:
                vuln = True
            elif script and not title and line.strip().startswith("|") and len(line.strip()) > 3:
                t = line.strip().lstrip("|_ ").strip()
                if t and ":" not in t[:4]:
                    title = t
        flush()
        return findings
