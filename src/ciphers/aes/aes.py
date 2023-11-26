from ...protocols import Blocks
from ..blocks import BlocksSinglePKCS7
from .consts import INV_SBOX_TABLE, POLY_MUL_TABLE, RCON_TABLE, SBOX_TABLE


class AES:
    def __init__(
        self,
        cipher_key: bytes,
        *,
        blocks_class: Blocks = BlocksSinglePKCS7,
    ) -> None:
        assert isinstance(cipher_key, bytes)
        assert len(cipher_key) == 16

        self._blocks_class = blocks_class

        self._key_schedule: bytearray = bytearray(cipher_key)
        self._key_expansion()

    def encrypt(self, data: bytes) -> bytes:
        blocks = self._blocks_class.to_blocks(data, block_size=16, padding=True)
        for block in blocks:
            self._encrypt_block(block)

        return self._blocks_class.from_blocks(blocks, padding=False)

    def decrypt(self, data: bytes) -> bytes:
        blocks = self._blocks_class.to_blocks(
            data, block_size=16, padding=False
        )
        for block in blocks:
            self._decrypt_block(block)

        return self._blocks_class.from_blocks(blocks, padding=True)

    def _encrypt_block(self, block: bytearray) -> None:
        self._add_round_key(block, 0)

        for r in range(1, 10):
            self._sub_bytes(block)
            self._shift_rows(block)
            self._mix_column(block)
            self._add_round_key(block, r)

        self._sub_bytes(block)
        self._shift_rows(block)
        self._add_round_key(block, 10)

    def _decrypt_block(self, block: bytearray) -> None:
        self._inverse_add_round_key(block, 10)
        self._inverse_shift_rows(block)
        self._inverse_sub_bytes(block)

        for r in range(9, 0, -1):
            self._inverse_add_round_key(block, r)
            self._inverse_mix_column(block)
            self._inverse_shift_rows(block)
            self._inverse_sub_bytes(block)

        self._inverse_add_round_key(block, 0)

    def _key_expansion(self) -> None:
        for r in range(10):
            word = self._key_schedule[-4:]
            self._rot_word(word)
            self._sub_word(word)

            for i in range(4):
                word[i] = (
                    word[i]
                    ^ RCON_TABLE[i + (4 * r)]
                    ^ self._key_schedule[i + (16 * r)]
                )
            self._key_schedule += word

            for k in range(1, 4):
                word = self._key_schedule[-4:]
                for i in range(4):
                    word[i] = (
                        word[i] ^ self._key_schedule[i + (k * 4) + (16 * r)]
                    )
                self._key_schedule += word

    @staticmethod
    def _rot_word(word: bytearray) -> None:
        w = word
        w[0], w[1], w[2], w[3] = w[1], w[2], w[3], w[0]

    @classmethod
    def _sub_word(cls, word: bytearray) -> None:
        cls._sub_bytes(word)

    @staticmethod
    def _sub_bytes(block: bytearray) -> None:
        for i, b in enumerate(block):
            block[i] = SBOX_TABLE[b]

    @staticmethod
    def _inverse_sub_bytes(block: bytearray) -> None:
        for i, b in enumerate(block):
            block[i] = INV_SBOX_TABLE[b]

    @staticmethod
    def _shift_rows(block: bytearray) -> None:
        b = block
        b[1], b[5], b[9], b[13] = b[5], b[9], b[13], b[1]
        b[2], b[6], b[10], b[14] = b[10], b[14], b[2], b[6]
        b[3], b[7], b[11], b[15] = b[15], b[3], b[7], b[11]

    @staticmethod
    def _inverse_shift_rows(block: bytearray) -> None:
        b = block
        b[1], b[5], b[9], b[13] = b[13], b[1], b[5], b[9]
        b[2], b[6], b[10], b[14] = b[10], b[14], b[2], b[6]
        b[3], b[7], b[11], b[15] = b[7], b[11], b[15], b[3]

    @staticmethod
    def _mix_column(block: bytearray) -> None:
        b = block
        mt = POLY_MUL_TABLE
        for i in range(0, 16, 4):
            # fmt: off
            n0 = mt[b[i], 0x02] ^ mt[b[i + 1], 0x03] ^ mt[b[i + 2], 0x01] ^ mt[b[i + 3], 0x01]
            n1 = mt[b[i], 0x01] ^ mt[b[i + 1], 0x02] ^ mt[b[i + 2], 0x03] ^ mt[b[i + 3], 0x01]
            n2 = mt[b[i], 0x01] ^ mt[b[i + 1], 0x01] ^ mt[b[i + 2], 0x02] ^ mt[b[i + 3], 0x03]
            n3 = mt[b[i], 0x03] ^ mt[b[i + 1], 0x01] ^ mt[b[i + 2], 0x01] ^ mt[b[i + 3], 0x02]
            # fmt: on
            b[i], b[i + 1], b[i + 2], b[i + 3] = n0, n1, n2, n3

    @staticmethod
    def _inverse_mix_column(block: bytearray) -> None:
        b = block
        mt = POLY_MUL_TABLE
        for i in range(0, 16, 4):
            # fmt: off
            n0 = mt[b[i], 0x0e] ^ mt[b[i + 1], 0x0b] ^ mt[b[i + 2], 0x0d] ^ mt[b[i + 3], 0x09]
            n1 = mt[b[i], 0x09] ^ mt[b[i + 1], 0x0e] ^ mt[b[i + 2], 0x0b] ^ mt[b[i + 3], 0x0d]
            n2 = mt[b[i], 0x0d] ^ mt[b[i + 1], 0x09] ^ mt[b[i + 2], 0x0e] ^ mt[b[i + 3], 0x0b]
            n3 = mt[b[i], 0x0b] ^ mt[b[i + 1], 0x0d] ^ mt[b[i + 2], 0x09] ^ mt[b[i + 3], 0x0e]
            # fmt: on
            b[i], b[i + 1], b[i + 2], b[i + 3] = n0, n1, n2, n3

    def _add_round_key(self, block: bytearray, round_num: int) -> None:
        for i in range(16):
            block[i] = block[i] ^ self._key_schedule[i + (round_num * 16)]

    def _inverse_add_round_key(self, block: bytearray, round_num: int) -> None:
        self._add_round_key(block, round_num)
