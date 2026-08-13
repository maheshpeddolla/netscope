from netscope.engines.scoring_engine import ScoringEngine


def test_scoring_engine_winner():
    engine = ScoringEngine()

    softnet = engine.hypothesis("Kernel Softnet")

    softnet.add(
        70,
        "softnet dropped > 0"
    )

    softnet.add(
        20,
        "time_squeeze > 0"
    )

    tcp = engine.hypothesis("TCP Stack")

    tcp.add(
        10,
        "TcpRetransSegs > 0"
    )

    driver = engine.hypothesis("NIC Driver")

    driver.add(
        30,
        "rx_dropped > 0"
    )

    winner = engine.winner()

    assert winner.name == "Kernel Softnet"
    assert winner.score == 90


def test_scoring_engine_ranking():

    engine = ScoringEngine()

    softnet = engine.hypothesis("Kernel Softnet")
    softnet.add(90, "softnet dropped > 0")

    driver = engine.hypothesis("NIC Driver")
    driver.add(30, "rx_dropped > 0")

    ranking = engine.ranking()

    assert ranking[0].name == "Kernel Softnet"
    assert ranking[1].name == "NIC Driver"