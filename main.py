from src.ciphers import Grasshopper, Magma
from src.utils.timer import timer


def grasshopper_run() -> None:
    gs = Grasshopper(cipher_key=b"\x01" * 32)
    en = gs.encrypt(b"Hello world")
    print(en)
    de = gs.decrypt(en)
    print(de)


def magma_run() -> None:
    magma = Magma(cipher_key=b"\x01" * 32)
    en = magma.encrypt(b"Hello world")
    print(en)
    de = magma.decrypt(en)
    print(de)


@timer
def main() -> None:
    # grasshopper_run()
    magma_run()


if __name__ == "__main__":
    main()
