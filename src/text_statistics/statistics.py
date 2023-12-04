from collections.abc import Mapping


def xi_square(
    frequencies: Mapping[str, float], default_frequencies: Mapping[str, float]
) -> float:
    total = 0.0
    for g in frequencies.keys():
        if default_frequencies[g] == 0.0:
            continue
        total += (frequencies[g] - default_frequencies[g]) ** 2 / default_frequencies[g]
    return total
