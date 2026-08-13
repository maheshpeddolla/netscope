from netscope.collectors.nic import collect_nic_stats


class FakeResult:
    success = True

    output = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    link/loopback 00:00:00:00:00:00
    RX: bytes packets errors dropped missed mcast
         0       0      0       0      0     0
    TX: bytes packets errors dropped carrier collsns
         0       0      0       0      0     0

2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 00:22:48:d6:23:b2
    RX: bytes packets errors dropped missed mcast
         42920361 9642 0 1 0 0
    TX: bytes packets errors dropped carrier collsns
         8311587 9546 0 0 0 0
"""

    stderr = ""


def test_collect_nic_stats(monkeypatch):

    monkeypatch.setattr(
        "netscope.collectors.nic.run_command",
        lambda command: FakeResult(),
    )

    result = collect_nic_stats()

    assert result["available"] is True

    assert "eth0" in result["interfaces"]

    eth0 = result["interfaces"]["eth0"]

    assert eth0["rx"]["bytes"] == 42920361
    assert eth0["rx"]["packets"] == 9642
    assert eth0["rx"]["errors"] == 0
    assert eth0["rx"]["dropped"] == 1

    assert eth0["tx"]["packets"] == 9546
    assert eth0["tx"]["dropped"] == 0