from src.ciphers import AES128
from src.utils.timer import timer

def aes_main() -> None:
    key = b"\xda\x13\x17\x65\x10\x4d\x98\x9f\x16\x04\x62\x1d\x4c\x5c\x38\x3b"

    aes = AES128(cipher_key=key)

    message = b"This is the test message for aes"

    cipher_message = aes.encrypt(message)

    print(cipher_message)
    decrypt_message = aes.decrypt(cipher_message)

    print(decrypt_message)

@timer
def main() -> None:
    aes_main()


if __name__ == "__main__":
    main()
