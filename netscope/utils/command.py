"""
NetScope Command Execution Engine

Provides a consistent and safe way to execute operating system commands.
All collectors must use this module instead of calling subprocess directly.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import List


@dataclass
class CommandResult:
    """
    Standard return object for every command execution.
    """

    success: bool
    command: str
    return_code: int
    stdout: str
    stderr: str
    duration_ms: int


def run_command(
    command: List[str],
    timeout: int = 10,
) -> CommandResult:
    """
    Execute a command safely.

    Args:
        command:
            Command as a list.
            Example:
                ["ip", "addr"]

        timeout:
            Timeout in seconds.

    Returns:
        CommandResult
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
        )

    except subprocess.TimeoutExpired:

        duration = int((time.perf_counter() - start) * 1000)

        return CommandResult(
            success=False,
            command=shlex.join(command),
            return_code=-1,
            stdout="",
            stderr=f"Command timed out after {timeout} seconds",
            duration_ms=duration,
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
        )