"""Session recording and report generation (JSON + Markdown)."""
from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from .agent import Plan


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def write_report(plan: Plan, out_dir: str = "reports", extra: dict | None = None) -> dict:
    out = Path(out_dir)
    out.mkdir(exist_ok=True)
    stamp = _ts()
    payload = {
        "generated_at": stamp,
        "findings": [asdict(f) for f in plan.findings],
        "planned_steps": plan.steps,
        **(extra or {}),
    }
    json_path = out / f"session_{stamp}.json"
    json_path.write_text(json.dumps(payload, indent=2))

    md = [f"# WiFi security test — {stamp}", "", "## Findings", ""]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for f in sorted(plan.findings, key=lambda x: order.get(x.severity, 9)):
        md += [f"### [{f.severity.upper()}] {f.title} — {f.ssid} ({f.bssid})",
               f"{f.detail}",
               f"**Recommendation:** {f.recommendation}" if f.recommendation else "", ""]
    md += ["## Planned / executed steps", ""]
    md += [f"- {s}" for s in plan.planned_steps] if hasattr(plan, "planned_steps") else [f"- {s}" for s in plan.steps]
    md_path = out / f"session_{stamp}.md"
    md_path.write_text("\n".join(md))
    return {"json": str(json_path), "markdown": str(md_path)}
