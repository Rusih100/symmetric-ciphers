from collections.abc import Mapping


def xi_square(
    frequencies: Mapping[str, float], default_frequencies: Mapping[str, float]
) -> float:
    total = 0.0
    for g in default_frequencies.keys():
        total += (default_frequencies[g] - frequencies[g]) ** 2 / frequencies[g]
    return total
