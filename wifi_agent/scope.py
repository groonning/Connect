"""Authorisation gate — now with runtime target adding (from the dashboard).

Adding a network to the target list IS the authorisation step: you are asserting
you own it or hold permission to test it. Every active operation still checks
this list before a tool runs.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
import yaml

_BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class ScopeError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    ssid: str
    bssid: str
    note: str = ""

    def __post_init__(self):
        if not _BSSID_RE.match(self.bssid):
            raise ValueError(f"invalid bssid: {self.bssid!r}")


class Scope:
    def __init__(self, targets: list[Target], path: Path | None = None):
        self._by_bssid = {t.bssid.upper(): t for t in targets}
        self._path = path

    @classmethod
    def load(cls, path: str | Path, create: bool = True) -> "Scope":
        path = Path(path)
        if not path.exists():
            if create:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("targets: []\n")
                return cls([], path=path)
            raise ScopeError(f"no authorised-targets file at {path}.")
        data = yaml.safe_load(path.read_text()) or {}
        raw = data.get("targets") or []
        targets = [Target(ssid=t.get("ssid", ""), bssid=t["bssid"],
                           note=t.get("note", "")) for t in raw]
        return cls(targets, path=path)

    def is_authorised(self, bssid: str) -> bool:
        return bssid.upper() in self._by_bssid

    def require(self, bssid: str) -> Target:
        t = self._by_bssid.get(bssid.upper())
        if t is None:
            raise ScopeError(
                f"{bssid} is NOT an authorised target — refusing to act. "
                "Add it as a target first (you confirm you have permission).")
        return t

    def all(self) -> list[Target]:
        return list(self._by_bssid.values())

    def add(self, bssid: str, ssid: str = "", note: str = "authorised via dashboard") -> Target:
        t = Target(ssid=ssid, bssid=bssid, note=note)
        self._by_bssid[bssid.upper()] = t
        self._save()
        return t

    def remove(self, bssid: str) -> None:
        self._by_bssid.pop(bssid.upper(), None)
        self._save()

    def _save(self) -> None:
        if not self._path:
            return
        data = {"targets": [{"ssid": t.ssid, "bssid": t.bssid, "note": t.note}
                            for t in self._by_bssid.values()]}
        self._path.write_text(yaml.safe_dump(data, sort_keys=False))
