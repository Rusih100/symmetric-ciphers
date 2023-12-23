from src.abc import BlockCipher
from src.bitwise_funcs import left_cyclic_shift
from src.ciphers.des.consts import (
    E_KEY_TABLE,
    E_TABLE,
    INV_IP_TABLE,
    IP_TABLE,
    KEY_SHIFT_TABLE,
    P_KEY_TABLE,
    P_TABLE,
    S_TABLE,
)


class DES(BlockCipher):
    _block_size = 8
    _key_size = 8

    def encrypt_block(self, block: bytearray) -> None:
        self._initial_permutation(block)

        left_bytes, right_bytes = block[:4], block[4:]
        left = int.from_bytes(left_bytes, byteorder="big")
        right = int.from_bytes(right_bytes, byteorder="big")

        for i in range(16):
            new_left = right
            new_right = left ^ self._f_function(right, self._key_schedule[i])

            left = new_left
            right = new_right

        left_bytes = bytearray(left.to_bytes(4, byteorder="big"))
        right_bytes = bytearray(right.to_bytes(4, byteorder="big"))

        block[:] = right_bytes + left_bytes
        self._inverse_initial_permutation(block)

    def decrypt_block(self, block: bytearray) -> None:
        self._initial_permutation(block)

        right_bytes, left_bytes = block[:4], block[4:]
        left = int.from_bytes(left_bytes, byteorder="big")
        right = int.from_bytes(right_bytes, byteorder="big")

        for i in range(15, -1, -1):
            new_right = left
            new_left = right ^ self._f_function(left, self._key_schedule[i])

            right = new_right
            left = new_left

        left_bytes = bytearray(left.to_bytes(4, byteorder="big"))
        right_bytes = bytearray(right.to_bytes(4, byteorder="big"))

        block[:] = left_bytes + right_bytes
        self._inverse_initial_permutation(block)

    def _init_key_schedule(self, cipher_key: bytes) -> None:
        self._key_schedule: list[int] = []

        key_bits = int.from_bytes(cipher_key, byteorder="big")

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

    @classmethod
    def _f_function(cls, right_bits: int, key: int) -> int:
        extension_bits = cls._expansion(right_bits)
        xor_bits = extension_bits ^ key

        sub_bits = cls._substitution(xor_bits)
        permutation_bits = cls._permutation(sub_bits)

        return permutation_bits

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
