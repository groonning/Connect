"""Planning / reporting layer.

Two parts, by design:
  - RuleBasedPlanner: deterministic severity flags from recon (always runs, safe).
  - Analyst: uses the local Ollama model to turn the facts into a readable
    Norwegian security report. The LLM only *describes*; it never decides what to
    attack — the scope gate in the tool layer stays authoritative.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from .scope import Scope
from . import llm


@dataclass
class Finding:
    bssid: str
    ssid: str
    severity: str
    title: str
    detail: str
    recommendation: str = ""

    def dict(self):
        return asdict(self)


class RuleBasedPlanner:
    def __init__(self, scope: Scope):
        self.scope = scope

    def assess(self, aps: list[dict]) -> list[Finding]:
        out = []
        for ap in aps:
            enc = (ap.get("encryption") or "").upper()
            ssid, bssid = ap.get("ssid", ""), ap.get("bssid", "")
            if "WEP" in enc:
                out.append(Finding(bssid, ssid, "high", "WEP-kryptering",
                                   "WEP er brutt og kan gjenopprettes raskt.",
                                   "Bytt til WPA2-AES eller WPA3."))
            elif "OPN" in enc or enc == "":
                out.append(Finding(bssid, ssid, "high", "Åpent nett",
                                   "All trafikk går i klartekst.", "Slå på WPA2/WPA3."))
            elif "WPA3" in enc:
                out.append(Finding(bssid, ssid, "info", "WPA3", "Sterkeste alternativ."))
        return out


class Analyst:
    """LLM-written report over the whole session."""
    SYSTEM = ("Du er en sikkerhetsanalytiker. Du skriver korte, konkrete rapporter "
              "på norsk om trådløs sikkerhet, basert KUN på dataene du får. Ikke "
              "finn på funn. Prioriter etter alvorlighet. Foreslå tiltak. Dette "
              "gjelder nett brukeren selv har tillatelse til å teste.")

    def __init__(self, scope: Scope):
        self.scope = scope

    def report(self, context: dict) -> dict:
        ok, msg = llm.available()
        if not ok:
            return {"ok": False, "error": msg}
        prompt = (
            "Skriv en kort sikkerhetsrapport (markdown) ut fra disse funnene.\n\n"
            f"Nettverk sett:\n{self._fmt_aps(context.get('aps', []))}\n\n"
            f"Autoriserte mål:\n{self._fmt_targets(context.get('targets', []))}\n\n"
            f"Crackede passord:\n{self._fmt_cracked(context.get('cracked', []))}\n\n"
            f"Enhets-svakheter:\n{self._fmt_dev(context.get('device_findings', []))}\n\n"
            "Struktur: ## Sammendrag, ## Funn (sortert på alvorlighet), ## Tiltak.")
        try:
            text = llm.chat(self.SYSTEM, prompt)
            return {"ok": True, "model": llm.MODEL, "report": text}
        except llm.OllamaError as e:
            return {"ok": False, "error": str(e)}

    @staticmethod
    def _fmt_aps(aps):
        return "\n".join(f"- {a.get('ssid','?')} ({a.get('bssid')}): "
                         f"{a.get('encryption','?')}, {a.get('clients',0)} enheter"
                         for a in aps) or "(ingen)"

    @staticmethod
    def _fmt_targets(ts):
        return "\n".join(f"- {t.get('ssid','?')} ({t.get('bssid')})" for t in ts) or "(ingen)"

    @staticmethod
    def _fmt_cracked(cs):
        return "\n".join(f"- {c.get('ssid','?')}: passord funnet" for c in cs) or "(ingen)"

    @staticmethod
    def _fmt_dev(fs):
        return "\n".join(f"- {f.get('mac','?')}: [{f.get('severity')}] {f.get('title')}"
                         for f in fs) or "(ingen)"
