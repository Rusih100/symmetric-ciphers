def caesars_shift(text: str, alphabet_chars: str, offset: int) -> str:
    alphabet_len = len(alphabet_chars)

    replace_map = {
        alphabet_chars[i]: alphabet_chars[(i + offset) % alphabet_len]
        for i in range(alphabet_len)
    }
    shift_text = ""
    for char in text:
        shift_text += replace_map[char]

    return shift_text
