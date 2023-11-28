from ...protocols import Blocks
from ..blocks import BlocksSinglePKCS7
from .consts import INV_IP_TABLE, IP_TABLE, E_TABLE


class DES:
    def __init__(
        self,
        cipher_key: bytes,
        *,
        blocks_class: Blocks = BlocksSinglePKCS7,
    ) -> None:
        assert isinstance(cipher_key, bytes)
        assert len(cipher_key) == 8

        self._blocks_class = blocks_class

    def encrypt(self, data: bytes) -> bytes:
        ...

    def decrypt(self, data: bytes) -> bytes:
        ...

    def _encrypt_block(self, block: bytearray) -> None:
        ...

    def _decrypt_block(self, block: bytearray) -> None:
        ...

    @staticmethod
    def _initial_permutation(block: bytearray) -> None:
        bits = int.from_bytes(block, byteorder="big")

        permutation_bits = 0
        for i, offset in enumerate(IP_TABLE):
            bit = (bits & (1 << offset)) >> offset
            permutation_bits |= bit << i

        block[:] = permutation_bits.to_bytes(length=8, byteorder="big")

    @staticmethod
    def _inverse_initial_permutation(block: bytearray) -> None:
        bits = int.from_bytes(block, byteorder="big")

        permutation_bits = 0
        for i, offset in enumerate(INV_IP_TABLE):
            bit = (bits & (1 << offset)) >> offset
            permutation_bits |= bit << i

        block[:] = permutation_bits.to_bytes(length=8, byteorder="big")

    @staticmethod
    def _f_function(bits: int, key: int) -> int:
        ...

    @staticmethod
    def _f_extension(bits: int) -> int:
        extension_bits = 0
        for i, offset in enumerate(E_TABLE):
            bit = (bits & (1 << offset)) >> offset
            extension_bits |= bit << i

        return extension_bits

    @staticmethod
    def _f_permutation(bits: int) -> int:
        ...
