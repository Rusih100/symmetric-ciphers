from typing import Final

# ruff: noqa: RUF001
# fmt: off
RUSSIAN_ALPHABET: Final[frozenset[str]] = frozenset(
    (
        "а", "б", "в", "г", "д", "е", "ё", "ж", "з", "и", "й",
        "к", "л", "м", "н", "о", "п", "р", "с", "т", "у", "ф",
        "х", "ц", "ч", "ш", "щ", "ъ", "ы", "ь", "э", "ю", "я",
        " ",
    )
)
# fmt: on


def process_russian_text(text: str) -> str:
    processed_text = ""

    for char in text:
        lower_char = char.lower()

        if lower_char == "\n":
            lower_char = " "

        if lower_char in RUSSIAN_ALPHABET:
            processed_text += lower_char

    processed_text = " ".join(processed_text.split())

    return processed_text
