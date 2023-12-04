from src.ciphers import AES, DES
from src.text_statistics import TextStatisticsReport
from src.utils.timer import timer

from src.text_statistics.process_text import process_russian_text
# ruff: noqa: RUF001


def lab1_main() -> None:
    text = process_russian_text(input("Введите текст:\n"))
    # print(text)
    print()

    report = TextStatisticsReport(text)
    print(f"Последовательность:\n{report.text}\n")
    print(f"Длина последовательности: {report.length}")
    print(f"Значковый xi_square: {report.xi_square_unigram}")
    print(f"Биграмный xi_square: {report.xi_square_bigram}")

    fr = 0.001
    print(f"Все триграммы частота встречаемости которых превышает {fr}")
    print(f"{report.trigram_frequencies(fr)}\n")

    k = 1000
    print("Все повторения участков последовательности, длина которых превышает")
    print(report.ngram_frequencies(k))


def aes_main() -> None:
    key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

    aes = AES(cipher_key=key, cipher_mode="ctr")

    message = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"

    cipher_message = aes.encrypt(message)

    print(cipher_message.hex())
    decrypt_message = aes.decrypt(cipher_message)

    print(decrypt_message)


def des_main() -> None:
    key = b"\x00\x01\x02\x03\x04\x05\x06\x07"

    des = DES(cipher_key=key)

    message = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"

    cipher_message = des.encrypt(message)

    print(cipher_message.hex())
    decrypt_message = des.decrypt(cipher_message)
    print(decrypt_message)


@timer
def main() -> None:
    # des_main()
    # aes_main()
    lab1_main()
    pass


if __name__ == "__main__":
    main()
