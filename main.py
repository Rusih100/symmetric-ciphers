from src.ciphers.grasshopper import Grasshopper
from src.utils.timer import timer


@timer
def main() -> None:
    gs = Grasshopper(cipher_key=b"\x01" * 32)
    en = gs.encrypt(b"Hello world")
    print(en)
    de = gs.decrypt(en)
    print(de)


if __name__ == "__main__":
    main()
