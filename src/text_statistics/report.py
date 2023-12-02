from collections.abc import Callable, Mapping

from src.text_statistics.default_frequencies import (
    BIGRAM_FREQUENCIES,
    UNIGRAM_FREQUENCIES,
)
from src.text_statistics.grams import (
    bigram_frequencies,
    ngram_frequencies,
    unigram_frequencies,
)
from src.text_statistics.process_text import process_russian_text
from src.text_statistics.statistics import xi_square


class TextStatisticsReport:
    def __init__(
        self,
        text: str,
        *,
        default_unigram_frequencies: Mapping[str, float] = UNIGRAM_FREQUENCIES,
        default_bigram_frequencies: Mapping[str, float] = BIGRAM_FREQUENCIES,
        process_text_func: Callable[[str], str] = process_russian_text,
    ) -> None:
        self._process_func = process_text_func
        self._default_unigram_freq = default_unigram_frequencies
        self._default_bigram_freq = default_bigram_frequencies

        self._text = self._process_func(text)
        self._unigram_freq = unigram_frequencies(self._text)
        self._bigram_freq = bigram_frequencies(self._text)

    @property
    def length(self) -> int:
        return len(self._text)

    @property
    def text(self) -> str:
        return self._text

    @property
    def xi_square_unigram(self) -> float:
        return xi_square(self._unigram_freq, self._default_unigram_freq)

    @property
    def xi_square_bigram(self) -> float:
        return xi_square(self._bigram_freq, self._default_bigram_freq)

    def trigram_frequencies(self, threshold: float) -> dict[str, float]:
        frequencies = ngram_frequencies(self._text, 3)
        filter_frequencies = filter(
            lambda x: x[1] >= threshold, frequencies.items()
        )
        sorted_frequencies = sorted(
            filter_frequencies, key=lambda x: x[1], reverse=True
        )
        return dict(sorted_frequencies)

    def ngram_frequencies(self, size: int) -> dict[str, float]:
        frequencies: dict[str, float] = {}
        for s in range(size, self.length + 1):
            frequencies |= ngram_frequencies(self._text, s)

        sorted_frequencies = sorted(
            frequencies.items(), key=lambda x: len(x[0]), reverse=True
        )
        return dict(sorted_frequencies)
