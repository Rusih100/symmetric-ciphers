from copy import copy

from src.ciphers import AES
from src.utils.timer import timer

from src.ciphers import AES
from src.text_statistics import TextStatisticsReport
from src.utils.timer import timer

# ruff: noqa: RUF001


def lab1_main() -> None:
    text = input("Введите текст:\n")
    report = TextStatisticsReport(text)
    print(f"Последовательность:\n{report.text}\n")
    print(f"Длина последовательности: {report.length}")
    print(f"Значковый xi_square: {report.xi_square_unigram}")
    print(f"Биграмный xi_square: {report.xi_square_bigram}")

    f = 0.1
    print(f"Все триграммы частота встречаемости которых превышает {f}")
    print(f"{report.trigram_frequencies(f)}\n")

    k = 4
    print("Все повторения участков последовательности, длина которых превышает")
    print(report.ngram_frequencies(k))

    
def aes_main() -> None:
    key = b"\xda\x13\x17\x65\x10\x4d\x98\x9f\x16\x04\x62\x1d\x4c\x5c\x38\x3b"

    aes = AES(cipher_key=key)

    message = b"This is the test message for aes"

    cipher_message = aes.encrypt(message)

    print(cipher_message)
    decrypt_message = aes.decrypt(cipher_message)

    print(decrypt_message)
    
@timer
def main() -> None:
    # aes_main()
    lab1_main()

if __name__ == "__main__":
    main()
