from copy import copy

from src.ciphers import AES, DES
from src.utils.timer import timer


def aes_main() -> None:
    key = b"\xda\x13\x17\x65\x10\x4d\x98\x9f\x16\x04\x62\x1d\x4c\x5c\x38\x3b"

    aes = AES(cipher_key=key)

    message = b"This is the test message for aes"

    cipher_message = aes.encrypt(message)

    print(cipher_message)
    decrypt_message = aes.decrypt(cipher_message)

    print(decrypt_message)


def des_main() -> None:
    block = bytearray(b"\x00\x00\xc4\xc2\xce\xd0\xdf\xca")
    print(block.hex())
    b = copy(block)
    DES._initial_permutation(block)
    print(block.hex())
    assert block == bytearray(b"\xfc\x60\x54\x40\xfc\x00\xd0\xd8")


@timer
def main() -> None:
    # aes_main()
    # des_main()
    ...


if __name__ == "__main__":
    main()
