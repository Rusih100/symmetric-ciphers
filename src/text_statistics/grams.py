from collections import Counter


def unigram_frequencies(text: str) -> dict[str, float]:
    counter = Counter(text)
    return {char: count / len(text) for char, count in counter.items()}


def bigram_frequencies(text: str) -> dict[str, float]:
    return ngram_frequencies(text, 2)


def ngram_frequencies(text: str, size: int) -> dict[str, float]:
    counter: dict[str, int] = {}

    for i in range(0, len(text) - size + 1):
        n_gram = text[i : i + size]
        if n_gram in counter:
            counter[n_gram] += 1
        else:
            counter[n_gram] = 1

    return {
        char: count / (len(text) - size + 1) for char, count in counter.items()
    }
