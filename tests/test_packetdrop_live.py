from netscope.diagnose.packetdrop_engine import diagnose_softnet
from netscope.monitors.packetdrop import monitor_packet_drops


def test_live_softnet_packet_drop():

    before = {
        "available": True,
        "cpus": [
            {
                "cpu": 0,
                "processed": 1000,
                "dropped": 10,
                "time_squeeze": 5,
            },
            {
                "cpu": 1,
                "processed": 2000,
                "dropped": 20,
                "time_squeeze": 8,
            },
        ],
    }

    after = {
        "available": True,
        "cpus": [
            {
                "cpu": 0,
                "processed": 1200,
                "dropped": 10,
                "time_squeeze": 6,
            },
            {
                "cpu": 1,
                "processed": 2500,
                "dropped": 27,
                "time_squeeze": 12,
            },
        ],
    }

    result = diagnose_softnet(
        before,
        after,
    )

    assert result.location == "Kernel Softnet"
    assert result.confidence == 70
    assert result.severity == "warning"

    assert "7 new softnet packet drops" in result.evidence[0]
    assert "CPU(s): 1" in result.evidence[0]


def test_live_softnet_no_packet_drop():

    before = {
        "available": True,
        "cpus": [
            {
                "cpu": 0,
                "processed": 1000,
                "dropped": 10,
                "time_squeeze": 5,
            },
        ],
    }

    after = {
        "available": True,
        "cpus": [
            {
                "cpu": 0,
                "processed": 1200,
                "dropped": 10,
                "time_squeeze": 5,
            },
        ],
    }

    result = diagnose_softnet(
        before,
        after,
    )

    assert result.location == "No Drop Detected"
    assert result.confidence == 0


def test_monitor_packet_drops(monkeypatch):

    snapshots = [
        {
            "available": True,
            "cpus": [
                {
                    "cpu": 0,
                    "processed": 1000,
                    "dropped": 10,
                    "time_squeeze": 5,
                },
            ],
        },
        {
            "available": True,
            "cpus": [
                {
                    "cpu": 0,
                    "processed": 1200,
                    "dropped": 15,
                    "time_squeeze": 7,
                },
            ],
        },
    ]

    def fake_read_softnet_stat():

        return snapshots.pop(0)

    monkeypatch.setattr(
        "netscope.monitors.packetdrop.read_softnet_stat",
        fake_read_softnet_stat,
    )

    # Prevent the test from actually waiting 10 seconds.
    monkeypatch.setattr(
        "netscope.monitors.packetdrop.time.sleep",
        lambda seconds: None,
    )

    results = monitor_packet_drops(
        interval=10,
        iterations=1,
    )

    assert len(results) == 1

    diagnosis = results[0]

    assert diagnosis.location == "Kernel Softnet"
    assert diagnosis.confidence == 70

    assert "5 new softnet packet drops" in diagnosis.evidence[0]