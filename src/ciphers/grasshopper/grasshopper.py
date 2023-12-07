from src.abc import BlockCipher


class Grasshopper(BlockCipher):
    _block_size = 16
    _key_size = 32

    def _init_key_schedule(self, cipher_key: bytes) -> None:
        pass

    def encrypt_block(self, block: bytearray) -> None:
        pass

    def decrypt_block(self, block: bytearray) -> None:
        pass

    