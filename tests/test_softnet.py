from pathlib import Path

from netscope.monitors.softnet import read_softnet_stat


def test_softnet_stat_parser(tmp_path):

    sample = (
        "00000010 00000002 00000001 00000000\n"
        "00000020 00000005 00000003 00000000\n"
    )

    test_file = tmp_path / "softnet_stat"

    test_file.write_text(sample)

    result = read_softnet_stat(test_file)

    assert result["available"] is True

    assert len(result["cpus"]) == 2

    assert result["cpus"][0]["cpu"] == 0
    assert result["cpus"][0]["processed"] == 16
    assert result["cpus"][0]["dropped"] == 2
    assert result["cpus"][0]["time_squeeze"] == 1

    assert result["cpus"][1]["cpu"] == 1
    assert result["cpus"][1]["processed"] == 32
    assert result["cpus"][1]["dropped"] == 5
    assert result["cpus"][1]["time_squeeze"] == 3


def test_softnet_unavailable(tmp_path):

    missing_file = tmp_path / "does_not_exist"

    result = read_softnet_stat(missing_file)

    assert result["available"] is False
    assert result["cpus"] == []