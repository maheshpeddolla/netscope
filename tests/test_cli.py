from netscope.cli import main


def test_cli_help(monkeypatch, capsys):

    monkeypatch.setattr(
        "sys.argv",
        [
            "netscope",
            "--help",
        ],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 0

    output = capsys.readouterr().out

    assert "NetScope Linux troubleshooting tool" in output
    assert "monitor" in output


def test_packetdrop_help(monkeypatch, capsys):

    monkeypatch.setattr(
        "sys.argv",
        [
            "netscope",
            "monitor",
            "packetdrop",
            "--help",
        ],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 0

    output = capsys.readouterr().out

    assert "usage:" in output
    assert "packetdrop" in output
    assert "--interval" in output
    assert "--iterations" in output