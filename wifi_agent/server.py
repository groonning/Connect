"""Local dashboard server. On the Kali box:
    sudo python3 -m wifi_agent.server --iface wlan0mon
Open http://127.0.0.1:8777 . Authorised use only.
"""
from __future__ import annotations
import argparse
import os
from flask import Flask, jsonify, request, send_from_directory
from .scope import Scope, ScopeError
from .scanner import LiveScanner
from .jobs import JobManager
from .traffic import TrafficInspector
from .devices import DeviceAudit
from . import preflight, llm
from .agent import Analyst, RuleBasedPlanner

HERE = os.path.dirname(__file__)
CONFIG = os.environ.get("WIFI_TARGETS", "config/authorized_targets.yaml")
WORDLIST = os.environ.get("WIFI_WORDLIST", "/usr/share/wordlists/rockyou.txt")


def _phase() -> str:
    try:
        return open(".run/phase").read().strip() or "1"
    except Exception:
        return "1"


def create_app(iface: str, autostart: bool = True) -> Flask:
    app = Flask(__name__, static_folder=os.path.join(HERE, "static"))
    scope = Scope.load(CONFIG)
    scanner = LiveScanner(iface)
    jobs = JobManager(scope, iface)
    audit = DeviceAudit(scope)
    analyst = Analyst(scope)
    planner = RuleBasedPlanner(scope)
    dev_store = {}   # mac -> [finding dicts]; in-memory only, lost on restart
    if autostart:
        scanner.start()                      # scanner comes up with the agent

    def cracked_keys() -> list[tuple[str, str]]:
        keys = []
        for key, j in jobs.snapshot().items():
            if j["kind"] == "crack" and j["password"]:
                t = next((x for x in scope.all() if x.bssid.upper() == j["bssid"].upper()), None)
                if t and t.ssid:
                    keys.append((j["password"], t.ssid))
        return keys

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "dashboard.html")

    @app.get("/api/tools")
    def tools():
        ok, msg = llm.available()
        t = preflight.check()
        t.append({"tool": "ollama ("+llm.MODEL+")", "package": "ollama", "use": msg, "ok": ok})
        return jsonify(tools=t)

    @app.get("/api/state")
    def state():
        data = scanner.read()
        data.update(targets=[t.__dict__ for t in scope.all()],
                    jobs=jobs.snapshot(), iface=iface, wordlist=WORDLIST,
                    auto=jobs.auto, auto_deauth=jobs.auto_deauth, phase=_phase(),
                    step1_complete=any(j['kind']=='crack' and j['password']
                                      for j in jobs.snapshot().values())
                                      or os.path.exists('.run/step1_done'),
                    decrypting=len(cracked_keys()))
        return jsonify(data)

    @app.post("/api/scan/start")
    def scan_start():
        scanner.start(); return jsonify(ok=True, running=scanner.running)

    @app.post("/api/scan/stop")
    def scan_stop():
        scanner.stop(); return jsonify(ok=True, running=scanner.running)

    @app.post("/api/targets/add")
    def target_add():
        b = request.json or {}
        try:
            t = scope.add(b["bssid"], b.get("ssid", ""),
                          b.get("note", "authorised via dashboard"))
            return jsonify(ok=True, target=t.__dict__)
        except Exception as e:
            return jsonify(ok=False, error=str(e)), 400

    @app.post("/api/targets/remove")
    def target_remove():
        b = request.json or {}
        scope.remove(b["bssid"]); return jsonify(ok=True)

    @app.post("/api/capture/start")
    def capture_start():
        b = request.json or {}
        try:
            j = jobs.start_capture(b["bssid"], b.get("channel", ""),
                                   bool(b.get("deauth", False)))
            return jsonify(ok=True, job=j.dict())
        except ScopeError as e:
            return jsonify(ok=False, error=str(e)), 403

    @app.post("/api/capture/stop")
    def capture_stop():
        b = request.json or {}
        jobs.stop_capture(b["bssid"]); return jsonify(ok=True)

    @app.post("/api/crack/start")
    def crack_start():
        b = request.json or {}
        try:
            j = jobs.start_crack(b["bssid"], b.get("wordlist", WORDLIST))
            return jsonify(ok=True, job=j.dict())
        except ScopeError as e:
            return jsonify(ok=False, error=str(e)), 403

    @app.post("/api/auto")
    def auto():
        b = request.json or {}
        jobs.set_auto(bool(b.get("on")), bool(b.get("deauth", False)),
                      b.get("wordlist", WORDLIST))
        return jsonify(ok=True, auto=jobs.auto, auto_deauth=jobs.auto_deauth)

    @app.get("/api/traffic")
    def traffic():
        only = request.args.get("only", "all")
        device = request.args.get("device", "")
        proto = request.args.get("proto", "")
        cap = scanner.latest_cap()
        insp = TrafficInspector(keys=cracked_keys())
        data = insp.read(cap, only=only, device=device, proto=proto)
        data["decrypting"] = bool(cracked_keys())
        return jsonify(data)

    @app.post("/api/devices/audit")
    def devices_audit():
        b = request.json or {}
        mac = b.get("mac", ""); enc = b.get("encryption", "")
        probes = b.get("probes", "")
        findings = [f.dict() for f in audit.passive(mac, enc, probes)]
        if b.get("active") and _phase() != "2":
            findings.append({"mac": mac, "ip": b.get("ip",""), "severity": "info",
                "title": "Aktiv skanning krever steg 2",
                "detail": "Kjør: sudo ./connect step2 \"SSID\" \"passord\" "
                          "— da er nett + CVE-oppslag aktivt."})
            if mac:
                dev_store[mac] = findings
            return jsonify(ok=True, findings=findings)
        if b.get("active") and b.get("ip") and b.get("bssid"):
            try:
                findings += [f.dict() for f in
                             audit.active_scan(mac, b["ip"], b["bssid"])]
            except ScopeError as e:
                return jsonify(ok=False, error=str(e)), 403
        if mac:
            dev_store[mac] = findings
        return jsonify(ok=True, findings=findings)

    @app.get("/api/llm")
    def llm_status():
        ok, msg = llm.available()
        return jsonify(ok=ok, model=llm.MODEL, detail=msg)

    def _aggregate():
        aps = scanner.read()["aps"]
        net = [f.dict() for f in planner.assess(aps)]
        devs = [f for lst in dev_store.values() for f in lst
                if f.get("severity") != "info"]
        cracked = [{"ssid": next((t.ssid for t in scope.all()
                    if t.bssid.upper()==j["bssid"].upper()), ""), "bssid": j["bssid"]}
                   for j in jobs.snapshot().values()
                   if j["kind"]=="crack" and j["password"]]
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        allf = sorted(net + devs, key=lambda f: order.get(f.get("severity"), 9))
        return {"aps": aps, "targets": [t.__dict__ for t in scope.all()],
                "cracked": cracked, "findings": allf,
                "device_findings": devs, "network_findings": net}

    @app.post("/api/report")
    def report():
        ctx = _aggregate()
        res = analyst.report(ctx)
        res["findings"] = ctx["findings"]      # structured, for JSON export
        return jsonify(res)

    return app


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8777)
    args = p.parse_args()
    miss = preflight.missing()
    if miss:
        print("[preflight] missing tools:", ", ".join(miss),
              "— run ./setup.sh")
    create_app(args.iface).run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
