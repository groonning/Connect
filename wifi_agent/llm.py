"""Local LLM via Ollama (http://localhost:11434). Pure stdlib, no extra deps.

Model selection (highest priority first):
    1. .run/model          — chosen in the dashboard (per-install)
    2. OLLAMA_MODEL env     — override at launch
    3. qwen3:30b-a3b        — default
"""
from __future__ import annotations
import json
import os
import subprocess
import urllib.request

URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:30b-a3b")
_MODEL_FILE = ".run/model"


class OllamaError(Exception):
    pass


def current_model() -> str:
    try:
        m = open(_MODEL_FILE).read().strip()
        if m:
            return m
    except Exception:
        pass
    return DEFAULT_MODEL


def set_model(name: str) -> None:
    os.makedirs(".run", exist_ok=True)
    with open(_MODEL_FILE, "w") as f:
        f.write(name.strip() + "\n")


# kept for back-compat; prefer current_model()
MODEL = current_model()


def list_models() -> list[str]:
    """Models pulled locally (via the Ollama API; falls back to the CLI)."""
    try:
        with urllib.request.urlopen(URL + "/api/tags", timeout=3) as r:
            tags = json.loads(r.read())
        return [m.get("name", "") for m in tags.get("models", []) if m.get("name")]
    except Exception:
        try:
            out = subprocess.run(["ollama", "list"], capture_output=True,
                                 text=True, timeout=5).stdout
            return [ln.split()[0] for ln in out.splitlines()[1:] if ln.strip()]
        except Exception:
            return []


def available() -> tuple[bool, str]:
    model = current_model()
    try:
        with urllib.request.urlopen(URL + "/api/tags", timeout=3) as r:
            tags = json.loads(r.read())
        names = [m.get("name", "") for m in tags.get("models", [])]
        if model in names:
            return True, model
        # tolerate tag suffixes (qwen3:30b-a3b vs qwen3:30b-a3b-instruct…)
        if any(n.split(":")[0] == model.split(":")[0] for n in names):
            return True, model + " (variant present)"
        return (bool(names),
                (f"model '{model}' ikke lastet ned; har: " + ", ".join(names)
                 if names else "ingen modeller lastet ned — kjør: ollama pull " + model))
    except Exception as e:
        return False, f"Ollama ikke tilgjengelig på {URL}: {e}"


def chat(system: str, user: str, as_json: bool = False, timeout: int = 300) -> str:
    body = {"model": current_model(), "stream": False,
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
