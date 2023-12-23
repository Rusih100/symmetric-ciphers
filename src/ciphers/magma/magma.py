from src.abc import BlockCipher
from src.bitwise_funcs import left_cyclic_shift
from src.bytes_funcs import repack_bytearray, repack_bytes
from src.ciphers.magma.consts import PI_TABLE


class Magma(BlockCipher):
    _block_size = 8
    _key_size = 32

    def _init_key_schedule(self, cipher_key: bytes) -> None:
        cipher_key = repack_bytes(cipher_key)

        base_keys: list[int] = [
            int.from_bytes(cipher_key[i : i + 4], byteorder="big")
            for i in range(0, 32, 4)
        ]
        self._key_schedule: list[int] = base_keys * 3 + base_keys[::-1]

    def encrypt_block(self, block: bytearray) -> None:
        repack_bytearray(block)

        left_bytes, right_bytes = block[:4], block[4:]
        left = int.from_bytes(left_bytes, byteorder="big")
        right = int.from_bytes(right_bytes, byteorder="big")

        for i in range(32):
            new_left = right
            new_right = left ^ self._g_function(right, self._key_schedule[i])

            left = new_left
            right = new_right

        left_bytes = bytearray(left.to_bytes(4, byteorder="big"))
        right_bytes = bytearray(right.to_bytes(4, byteorder="big"))

        block[:] = right_bytes + left_bytes
        repack_bytearray(block)

    def decrypt_block(self, block: bytearray) -> None:
        repack_bytearray(block)

        left_bytes, right_bytes = block[:4], block[4:]
        left = int.from_bytes(left_bytes, byteorder="big")
        right = int.from_bytes(right_bytes, byteorder="big")

        for i in range(31, -1, -1):
            new_left = right
            new_right = left ^ self._g_function(right, self._key_schedule[i])

            left = new_left
            right = new_right

        left_bytes = bytearray(left.to_bytes(4, byteorder="big"))
        right_bytes = bytearray(right.to_bytes(4, byteorder="big"))

        block[:] = right_bytes + left_bytes
        repack_bytearray(block)

    @classmethod
    def _g_function(cls, bits: int, key_bits: int) -> int:
        bits = cls._add_32bit(bits, key_bits)
        bits = cls._t_function(bits)
        bits = left_cyclic_shift(bits, 11, 32)
        return bits

    @staticmethod
    def _t_function(bits: int) -> int:
        sub_bits = 0
        bits_mask = 0b1111

        for i in range(8):
            raw_bits = (bits & bits_mask) >> (i * 4)
            value = PI_TABLE[i][raw_bits]

            sub_bits |= value << (i * 4)
            bits_mask = bits_mask << 4

        return sub_bits

    @staticmethod
    def _add_32bit(bits: int, other_bits: int) -> int:
        return (bits + other_bits) & 0xFFFFFFFF
