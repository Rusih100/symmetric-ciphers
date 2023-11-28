from collections import Counter


def unigram_frequencies(text: str) -> dict[str, float]:
    counter = Counter(text)
    return {char: count / len(text) for char, count in counter.items()}


def bigram_frequencies(text: str) -> dict[str, float]:
    counter: dict[str, int] = {}

    for i in range(0, len(text) - 1):
        bigram = text[i : i + 2]
        if bigram in counter:
            counter[bigram] += 1
        else:
            counter[bigram] = 1

    return {char: count / len(text) for char, count in counter.items()}
