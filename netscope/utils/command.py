"""
NetScope Command Execution Engine
"""

from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CommandResult:
    success: bool
    command: str
    return_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timestamp: str


def run_command(command: list[str], timeout: int = 10) -> CommandResult:
    """
    Execute a system command safely.
    """

    start = time.perf_counter()

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        duration = int((time.perf_counter() - start) * 1000)

        return CommandResult(
            success=result.returncode == 0,
            command=shlex.join(command),
            return_code=result.returncode,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            duration_ms=duration,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )

    except subprocess.TimeoutExpired:
        duration = int((time.perf_counter() - start) * 1000)

        return CommandResult(
            success=False,
            command=shlex.join(command),
            return_code=-1,
            stdout="",
            stderr=f"Timed out after {timeout} seconds",
            duration_ms=duration,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )

    except FileNotFoundError:
        duration = int((time.perf_counter() - start) * 1000)

        return CommandResult(
            success=False,
            command=shlex.join(command),
            return_code=-2,
            stdout="",
            stderr="Command not found",
            duration_ms=duration,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )

    except Exception as exc:
        duration = int((time.perf_counter() - start) * 1000)

        return CommandResult(
            success=False,
            command=shlex.join(command),
            return_code=-999,
            stdout="",
            stderr=str(exc),
            duration_ms=duration,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )