# WiFi Security Testing Agent

An agent that orchestrates wireless security tools (recon, handshake capture,
cracking, packet analysis) against **networks you are authorised to test**, and
produces structured findings reports.

## Installer og kjør

På Kali Linux:

```bash
git clone https://github.com/groonning/connect
cd connect
sudo ./connect install     # verktøy (aircrack-ng, wifite, tshark, nmap) + Ollama + modell + venv + ordliste + global `connect`
```

Legg nettet ditt i `config/authorized_targets.yaml`, så:

```bash
sudo connect start         # STEG 1: monitor mode — skann, fang håndtrykk, crack passord
#   dashbord: http://127.0.0.1:8777
sudo connect step2 "SSID" "passord"   # STEG 2: nett på — enhets- og CVE-skann
sudo connect stop          # stopper alt, kort tilbake, nett tilbake, Ollama ned
```

`connect start` tar nettet (monitor mode på ett kort); `connect step2` og `connect stop` gir det tilbake.
`connect help` viser alle kommandoer, `connect status` viser hvilken fase du er i.

## ⚠️ Authorisation — read first

This toolkit only runs active operations against targets you explicitly place in
`config/authorized_targets.yaml`. Testing a network you do not own, or do not
have **written permission** to test, is illegal in Norway under straffeloven
(datainnbrudd). The scope gate (`wifi_agent/scope.py`) is a hard block: any tool
action against a BSSID/SSID not on the authorised list is refused before the
tool starts. Do not remove it.

Use this on:
- your own home/office WiFi,
- a lab network you set up yourself,
- a client network where you hold a signed engagement/scope document.

## Hardware & OS reality

The orchestrator (this Python code) is OS-agnostic. The underlying tools are not:

- **Wireshark / tshark** — cross-platform, runs on macOS. Analysis only.
- **wifite2 / aircrack-ng / airodump-ng** — Linux, and need a WiFi adapter with
  **monitor mode + packet injection** (e.g. Atheros AR9271, Realtek RTL8812AU).
  macOS's built-in card won't do injection. Run these on a Linux box (Kali/Parrot
  in a VM, a Raspberry Pi, or a dedicated laptop) with the USB adapter attached.

Recommended setup: run the orchestrator on the same Linux box that has the
adapter. You can develop/edit here on the Mac and sync to that box.

## Layers

1. **Scope gate** (`scope.py`) — authorised-targets allowlist, enforced on every run.
2. **Tool wrappers** (`tools/`) — uniform interface around each CLI tool.
3. **Agent** (`agent.py`) — planning + result interpretation (pluggable LLM).
4. **Reporting** (`report.py`) — JSON + Markdown findings per session.

## Daglig bruk — `connect` (to steg)

First time: `./setup.sh` (installs tools + Ollama). Then the agent runs in two phases,
because one WiFi card can't be in monitor mode and on the network at the same time:

```bash
# STEG 1 — WiFi (monitor mode, no internet): scan, capture handshake, crack password
sudo connect step1
#   dashboard at http://127.0.0.1:8777

# STEG 2 — device analysis (network ON): vuln + CVE scanning of devices
sudo connect step2 "SSID" "passord"

sudo connect stop        # card back to normal, network back, Ollama down
connect status           # which phase + what is running
connect help             # colored command reference
```

Step 1 drops internet (monitor mode); step 2 and `connect stop` both restore it.
Bigger local model: `OLLAMA_MODEL=qwen3:30b-a3b sudo connect step1`.

Manual/low-level use is still available via `python3 cli.py scan --iface wlan0mon`.

## Status

Scaffold. Tool wrappers are functional skeletons: recon/parse logic is wired,
and each `run()` builds the real command but is guarded so nothing active fires
until you've set your interface and authorised targets. Fill in the LLM in
`agent.py` to get automated planning and report-writing.
