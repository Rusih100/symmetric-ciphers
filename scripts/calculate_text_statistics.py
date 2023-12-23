from pathlib import Path
from pprint import pprint

from src.text_statistics import (
    bigram_frequencies,
    process_russian_text,
    unigram_frequencies,
)

INPUT_FILE_PATH = Path(__file__).parent.parent / "data" / "war_and_peace.txt"
print(INPUT_FILE_PATH)

with open(INPUT_FILE_PATH, encoding="utf-8") as file:
    text = file.read()

processed_text = process_russian_text(text)

pprint(unigram_frequencies(processed_text))
print()
pprint(bigram_frequencies(processed_text))
