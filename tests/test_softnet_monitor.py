from netscope.monitors.softnet import (
    compare_softnet,
    detect_packet_drops,
)


def test_softnet_counter_delta():

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

    result = compare_softnet(
        before,
        after
    )

    assert result["available"] is True

    assert result["cpus"][0]["processed_delta"] == 200
    assert result["cpus"][0]["dropped_delta"] == 0
    assert result["cpus"][0]["time_squeeze_delta"] == 1

    assert result["cpus"][1]["processed_delta"] == 500
    assert result["cpus"][1]["dropped_delta"] == 7
    assert result["cpus"][1]["time_squeeze_delta"] == 4


def test_packet_drop_detection():

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

    result = detect_packet_drops(
        before,
        after
    )

    assert result["available"] is True
    assert result["drops_detected"] is True

    assert len(result["cpus"]) == 1

    assert result["cpus"][0]["cpu"] == 1
    assert result["cpus"][0]["dropped_delta"] == 7


def test_no_packet_drop():

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

    result = detect_packet_drops(
        before,
        after
    )

    assert result["available"] is True
    assert result["drops_detected"] is False
    assert result["cpus"] == []