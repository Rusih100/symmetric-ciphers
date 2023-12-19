from copy import copy

from src.abc import BlockCipher
from src.ciphers.grasshopper.consts import (
    INV_PI_TABLE,
    INV_ROTATE_TABLE,
    KEY_CONSTS,
    PI_TABLE,
    POLY_MUL_TABLE,
    ROTATE_TABLE,
)


class Grasshopper(BlockCipher):
    _block_size = 16
    _key_size = 32

    def _init_key_schedule(self, cipher_key: bytes) -> None:
        cipher_key = self._repack_bytes(cipher_key)

        first_block = bytearray(cipher_key[:16])
        second_block = bytearray(cipher_key[16:])

        self._key_schedule: list[bytearray] = [
            copy(first_block),
            copy(second_block),
        ]
        for key_consts in KEY_CONSTS:
            self._feistel_function(second_block, first_block, key_consts)
            self._key_schedule.append(copy(first_block))
            self._key_schedule.append(copy(second_block))

    def encrypt_block(self, block: bytearray) -> None:
        self._repack_bytearray(block)

        for i in range(9):
            self._xor_blocks(block, self._key_schedule[i])
            self._substitution(block)
            self._linear(block)

        self._xor_blocks(block, self._key_schedule[9])
        self._repack_bytearray(block)

    def decrypt_block(self, block: bytearray) -> None:
        self._repack_bytearray(block)
        self._xor_blocks(block, self._key_schedule[9])

        for i in range(8, -1, -1):
            self._inverse_linear(block)
            self._inverse_substitution(block)
            self._xor_blocks(block, self._key_schedule[i])

        self._repack_bytearray(block)

    @staticmethod
    def _substitution(block: bytearray) -> None:
        for i, b in enumerate(block):
            block[i] = PI_TABLE[b]

    @staticmethod
    def _inverse_substitution(block: bytearray) -> None:
        for i, b in enumerate(block):
            block[i] = INV_PI_TABLE[b]

    @classmethod
    def _linear(cls, block: bytearray) -> None:
        for _ in range(16):
            cls._rotate(block)

    @classmethod
    def _inverse_linear(cls, block: bytearray) -> None:
        for _ in range(16):
            cls._inverse_rotate(block)

    @staticmethod
    def _rotate(block: bytearray) -> None:
        xor_sum = 0
        for i, b in enumerate(block):
            xor_sum ^= POLY_MUL_TABLE[b, ROTATE_TABLE[i]]

        block.insert(0, xor_sum)
        block.pop()

    @staticmethod
    def _inverse_rotate(block: bytearray) -> None:
        xor_sum = 0
        for i, b in enumerate(block):
            xor_sum ^= POLY_MUL_TABLE[b, INV_ROTATE_TABLE[i]]

        block.append(xor_sum)
        block.pop(0)

    @classmethod
    def _feistel_function(
        cls,
        left_block: bytearray,
        right_block: bytearray,
        key_consts: tuple[bytearray, ...],
    ) -> None:
        for key_const in key_consts:
            f_block = copy(right_block)

            cls._xor_blocks(f_block, key_const)
            cls._substitution(f_block)
            cls._linear(f_block)
            cls._xor_blocks(left_block, f_block)

            left_block, right_block = right_block, left_block

    @staticmethod
    def _xor_blocks(block: bytearray, other_block: bytearray | bytes) -> None:
        for i in range(16):
            block[i] ^= other_block[i]

    @staticmethod
    def _repack_bytearray(block: bytearray) -> None:
        block[:] = reversed(block)

    @staticmethod
    def _repack_bytes(block: bytes) -> bytes:
        return bytes(reversed(block))
