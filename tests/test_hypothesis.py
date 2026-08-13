from netscope.engines.scoring_engine import ScoringEngine

engine = ScoringEngine()

softnet = engine.hypothesis("Kernel Softnet")
softnet.add(70, "softnet dropped > 0")
softnet.add(20, "time_squeeze > 0")
softnet.recommend("Check CPU utilization")
softnet.recommend("Check IRQ affinity")

driver = engine.hypothesis("NIC Driver")
driver.add(30, "rx_dropped > 0")
driver.recommend("Check ring buffer")

winner = engine.winner()

print("Winner")
print("------")
print(winner)

print()

print("Ranking")
print("-------")

for item in engine.ranking():
    print(item)