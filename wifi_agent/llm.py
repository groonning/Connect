"""Local LLM via Ollama (http://localhost:11434). Pure stdlib, no extra deps.

The agent runs fully offline on the Kali box. Model is configurable:
    OLLAMA_MODEL (default qwen3:30b-a3b)   OLLAMA_URL (default localhost:11434)
"""
from __future__ import annotations
import json
import os
import urllib.request

URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:30b-a3b")


class OllamaError(Exception):
    pass


def available() -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(URL + "/api/tags", timeout=3) as r:
            tags = json.loads(r.read())
        names = [m.get("name", "") for m in tags.get("models", [])]
        return True, (MODEL if MODEL in names else
                      (f"model '{MODEL}' not pulled; have: " + ", ".join(names) if names
                       else "no models pulled"))
    except Exception as e:
        return False, f"Ollama not reachable at {URL}: {e}"


def chat(system: str, user: str, as_json: bool = False, timeout: int = 180) -> str:
    body = {"model": MODEL, "stream": False,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]}
    if as_json:
        body["format"] = "json"
    req = urllib.request.Request(URL + "/api/chat",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        return data.get("message", {}).get("content", "")
    except Exception as e:
        raise OllamaError(str(e))
