from collections import defaultdict


def summarize(evidence):

    groups = defaultdict(list)

    for item in evidence:

        groups[item.location].append(item)

    return groups