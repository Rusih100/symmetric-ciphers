from ...bitwise_funcs import left_cyclic_shift
from ...protocols import Blocks
from ..blocks import BlocksSinglePKCS7
from .consts import (
    E_KEY_TABLE,
    E_TABLE,
    INV_IP_TABLE,
    IP_TABLE,
    KEY_SHIFT_TABLE,
    P_KEY_TABLE,
    P_TABLE,
    S_TABLE,
)


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

        self._cipher_key = cipher_key
        self._key_schedule: list[int] = []
        self._init_key_schedule()

    def encrypt(self, data: bytes) -> bytes:
        ...

    def decrypt(self, data: bytes) -> bytes:
        ...

    def _encrypt_block(self, block: bytearray) -> None:
        ...

    def _decrypt_block(self, block: bytearray) -> None:
        ...

    def _init_key_schedule(self) -> None:
        key_bits = int.from_bytes(self._cipher_key, byteorder="big")

        key_bits = self._key_permutation(key_bits)
        for shift in KEY_SHIFT_TABLE:
            key_bits = self._key_rotate(key_bits, shift)

            key = self._key_expansion(key_bits)
            self._key_schedule.append(key)

    @staticmethod
    def _key_permutation(bits: int) -> int:
        permutation_bits = 0
        for i, offset in enumerate(P_KEY_TABLE):
            bit = (bits >> (63 - offset)) & 1
            permutation_bits |= bit << (55 - i)

        return permutation_bits

    @staticmethod
    def _key_rotate(bits: int, shift: int) -> int:
        left_key = bits >> 28
        right_key = bits & 0xFFFFFFF

        left_key = left_cyclic_shift(left_key, shift, 28)
        right_key = left_cyclic_shift(right_key, shift, 28)

        return (left_key << 28) | right_key

    @staticmethod
    def _key_expansion(bits: int) -> int:
        extension_bits = 0
        for i, offset in enumerate(E_KEY_TABLE):
            bit = (bits >> (55 - offset)) & 1
            extension_bits |= bit << (47 - i)

        return extension_bits

    @staticmethod
    def _initial_permutation(block: bytearray) -> None:
        bits = int.from_bytes(block, byteorder="big")

        permutation_bits = 0
        for i, offset in enumerate(IP_TABLE):
            bit = (bits >> offset) & 1
            permutation_bits |= bit << i

        block[:] = permutation_bits.to_bytes(length=8, byteorder="big")

    @staticmethod
    def _inverse_initial_permutation(block: bytearray) -> None:
        bits = int.from_bytes(block, byteorder="big")

        permutation_bits = 0
        for i, offset in enumerate(INV_IP_TABLE):
            bit = (bits >> offset) & 1
            permutation_bits |= bit << i

        block[:] = permutation_bits.to_bytes(length=8, byteorder="big")

    @staticmethod
    def _feistel_function(bits: int, key: int) -> int:
        ...

    @staticmethod
    def _expansion(bits: int) -> int:
        extension_bits = 0
        for i, offset in enumerate(E_TABLE):
            bit = (bits >> offset) & 1
            extension_bits |= bit << i

        return extension_bits

    @staticmethod
    def _substitution(bits: int) -> int:
        sub_bits = 0

        bits_mask = 0b111111 << 42
        for i in range(8):
            s_bits = (bits & bits_mask) >> 6 * (7 - i)
            row = 2 * ((s_bits >> 5) & 1) + (s_bits & 1)
            column = (
                8 * ((s_bits >> 4) & 1)
                + 4 * ((s_bits >> 3) & 1)
                + 2 * ((s_bits >> 2) & 1)
                + ((s_bits >> 1) & 1)
            )
            value = S_TABLE[i][row][column]
            sub_bits |= value << 4 * (7 - i)

            bits_mask = bits_mask >> 6

        return sub_bits

    @staticmethod
    def _permutation(bits: int) -> int:
        permutation_bits = 0
        for i, offset in enumerate(P_TABLE):
            bit = (bits >> (31 - offset)) & 1
            permutation_bits |= bit << (31 - i)

        return permutation_bits
