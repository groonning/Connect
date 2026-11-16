"""Thin, logged subprocess wrapper so every tool invocation is uniform and
auditable. Commands are passed as arg lists (no shell) to avoid injection.
"""
from __future__ import annotations
import subprocess
import shutil
import time
from dataclasses import dataclass, field


@dataclass
class RunResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    started_at: float = field(default_factory=time.time)


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run(cmd: list[str], timeout: int | None = None, dry_run: bool = False) -> RunResult:
    """Run a command. dry_run returns the command without executing it."""
    start = time.time()
    if dry_run:
        return RunResult(cmd=cmd, returncode=0, stdout=f"[dry-run] {' '.join(cmd)}",
                         stderr="", seconds=0.0)
    if not tool_available(cmd[0]):
        return RunResult(cmd=cmd, returncode=127, stdout="",
                         stderr=f"{cmd[0]} not installed on this host", seconds=0.0)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return RunResult(cmd=cmd, returncode=proc.returncode, stdout=proc.stdout,
                         stderr=proc.stderr, seconds=time.time() - start)
    except subprocess.TimeoutExpired as e:
        return RunResult(cmd=cmd, returncode=124, stdout=e.stdout or "",
                         stderr=f"timeout after {timeout}s", seconds=time.time() - start)
