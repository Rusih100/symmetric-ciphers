from .consts import INV_SBOX_TABLE, POLY_MUL_TABLE, RCON_TABLE, SBOX_TABLE


class AES128:
    def __init__(self, *, cipher_key: bytes) -> None:
        assert isinstance(cipher_key, bytes)
        assert len(cipher_key) == 16

        self._key_schedule: bytearray = bytearray(cipher_key)
        self._key_expansion()

    def _key_expansion(self) -> None:
        for r in range(0, 9):
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

    def _add_round_key(self, block: bytearray) -> None:
        ...

    def _inverse_add_round_key(self, block: bytearray) -> None:
        ...


# TODO: Написать алгоритм генерации раундовых ключей
# TODO: Написать алгоритм _add_round_key
# TODO: Написать разбиение на блоки
# TODO: Написать алгоритм шифрования
# TODO: Написать алгоритм расшифрования
