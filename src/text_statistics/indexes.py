from collections import Counter


def coincidence_index(text: str) -> float:
    chars_freq = Counter(text)
    freq_sum = sum(freq * (freq - 1) for freq in chars_freq.values())

    return freq_sum / (len(text) * (len(text) - 1))


def mutual_coincidence_index(first_text: str, second_text: str) -> float:
    first_chars_freq = Counter(first_text)
    second_chars_freq = Counter(second_text)

    unique_chars = frozenset(first_text + second_text)

    freq_sum = sum(
        first_chars_freq[char] * second_chars_freq[char]
        for char in unique_chars
    )
    return freq_sum / (len(first_text) * len(second_text))
