def check_word_by_pattern(word: str, pattern: str) -> bool:
    if len(pattern) != len(word):
        return False
    if len(set(pattern)) != len(set(word)):
        return False

    replace_map: dict[str, str] = dict(
        zip(word, pattern)
    )
    check_word = ""
    for char in word:
        check_word += replace_map[char]

    return check_word == pattern


def get_update_decrypt_alphabet(
    word: str, pattern: str, alphabet: dict[str, str]
) -> dict[str, str]:

    updated_alphabet: dict[str, str] = {}
    for i, char in enumerate(word):
        if char not in alphabet:
            updated_alphabet[char] = pattern[i]
        elif alphabet[char] != pattern[i]:
            return {}

    if set(alphabet.values()) & set(updated_alphabet.values()):
        return {}
    return updated_alphabet


def search_word_by_pattern(
    pattern: str, text: str, alphabet: dict[str, str]
) -> tuple[str | None, dict[str, str]]:
    pattern_length = len(pattern)
    text_length = len(text)

    for i in range(text_length - pattern_length + 1):
        word = text[i : i + pattern_length]

        if not check_word_by_pattern(word, pattern):
            continue

        updated_alphabet = get_update_decrypt_alphabet(word, pattern, alphabet)
        if not updated_alphabet:
            continue

        return word, updated_alphabet

    return None, {}




