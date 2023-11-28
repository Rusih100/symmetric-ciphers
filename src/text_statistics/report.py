from collections.abc import Callable, Mapping

from .process_text import process_russian_text
from .statistics import xi_square
from .grams import bigram_frequencies, unigram_frequencies
from .default_frequencies import UNIGRAM_FREQUENCIES, BIGRAM_FREQUENCIES


class StatisticsReport:
    def __init__(
        self,
        text: str,
        *,
        default_unigram_frequencies: Mapping[str, float] = UNIGRAM_FREQUENCIES,
        default_bigram_frequencies: Mapping[str, float] = BIGRAM_FREQUENCIES,
        process_text_func: Callable[[str], str] = process_russian_text
    ) -> None:
        self._process_func = process_text_func
        self._text = self._process_func(text)

    def length(self) -> int:
        return len(self._text)

