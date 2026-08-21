"""Tests for linuxnetlens.cli."""

from __future__ import annotations

from pathlib import Path

import pytest

from linuxnetlens.cli import main


FIXTURES = Path(__file__).resolve().parent.parent / "examples" / "linuxnetlens"


def test_info_command_runs(capsys):
    rc = main(["info"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "available backends" in out.lower()


def test_diagnose_blocked_fixture(capsys):
    rc = main([
        "diagnose",
        "--replay", str(FIXTURES / "blocked_nft.json"),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "LinuxNetLens Network Diagnosis" in out
    assert "Source" in out
    assert "Destination" in out
    assert "Protocol" in out
    assert "Process" in out
    assert "PID" in out
    assert "Result" in out
    assert "BLOCKED" in out
    assert "Blocked By" in out
    assert "Hook" in out
    assert "Action" in out
    assert "Confidence" in out


def test_diagnose_no_response_never_reports_blocked_section(capsys):
    """The overclaim regression guard, expressed in CLI output."""
    rc = main([
        "diagnose",
        "--replay", str(FIXTURES / "no_response.json"),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "NO_RESPONSE" in out
    assert "BLOCKED" not in out
    assert "Blocked By" not in out


def test_diagnose_json_output(capsys):
    rc = main([
        "diagnose",
        "--replay", str(FIXTURES / "blocked_nft.json"),
        "--json",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "\"outcome\": \"BLOCKED\"" in out
    assert "\"location\": \"Firewall (netfilter)\"" in out


def test_diagnose_refuses_broad_capture_without_confirmation(capsys):
    rc = main(["diagnose"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "confirm-broad" in err


def test_diagnose_invalid_flow_returns_error(capsys):
    rc = main([
        "diagnose",
        "--flow", "not-a-flow",
        "--replay", str(FIXTURES / "unknown_empty.json"),
    ])
    err = capsys.readouterr().err
    assert rc == 2
    assert "invalid --flow" in err


def test_version_flag(capsys):
    rc = main(["--version"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "linuxnetlens" in out.lower()
