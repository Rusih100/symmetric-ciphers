from .consts import INV_SUB_BYTES_TABLE, POLY_MUL_TABLE, SUB_BYTES_TABLE


class AES128:
    def __init__(self) -> None:
        ...

    @staticmethod
    def _sub_bytes(block: bytearray) -> None:
        for i, b in enumerate(block):
            block[i] = SUB_BYTES_TABLE[b]

    @staticmethod
    def _inverse_sub_bytes(block: bytearray) -> None:
        for i, b in enumerate(block):
            block[i] = INV_SUB_BYTES_TABLE[b]

    @staticmethod
    def _shift_rows(block: bytearray) -> None:
        b = block
        b[4], b[5], b[6], b[7] = b[5], b[6], b[7], b[4]
        b[8], b[9], b[10], b[11] = b[10], b[11], b[8], b[9]
        b[12], b[13], b[14], b[15] = b[15], b[12], b[13], b[14]

    @staticmethod
    def _inverse_shift_rows(block: bytearray) -> None:
        b = block
        b[4], b[5], b[6], b[7] = b[7], b[4], b[5], b[6]
        b[8], b[9], b[10], b[11] = b[10], b[11], b[8], b[9]
        b[12], b[13], b[14], b[15] = b[13], b[14], b[15], b[12]

    @staticmethod
    def _mix_column(block: bytearray) -> None:
        b = block
        mt = POLY_MUL_TABLE
        for i in range(4):
            # fmt: off
            n0 = mt[b[i], 0x02] ^ mt[b[i + 4], 0x03] ^ mt[b[i + 8], 0x01] ^ mt[b[i + 12], 0x01]
            n1 = mt[b[i], 0x01] ^ mt[b[i + 4], 0x02] ^ mt[b[i + 8], 0x03] ^ mt[b[i + 12], 0x01]
            n2 = mt[b[i], 0x01] ^ mt[b[i + 4], 0x01] ^ mt[b[i + 8], 0x02] ^ mt[b[i + 12], 0x03]
            n3 = mt[b[i], 0x03] ^ mt[b[i + 4], 0x01] ^ mt[b[i + 8], 0x01] ^ mt[b[i + 12], 0x02]
            # fmt: on
            b[i], b[i + 4], b[i + 8], b[i + 12] = n0, n1, n2, n3

    @staticmethod
    def _inverse_mix_column(block: bytearray) -> None:
        b = block
        mt = POLY_MUL_TABLE
        for i in range(4):
            # fmt: off
            n0 = mt[b[i], 0x0e] ^ mt[b[i + 4], 0x0b] ^ mt[b[i + 8], 0x0d] ^ mt[b[i + 12], 0x09]
            n1 = mt[b[i], 0x09] ^ mt[b[i + 4], 0x0e] ^ mt[b[i + 8], 0x0b] ^ mt[b[i + 12], 0x0d]
            n2 = mt[b[i], 0x0d] ^ mt[b[i + 4], 0x09] ^ mt[b[i + 8], 0x0e] ^ mt[b[i + 12], 0x0b]
            n3 = mt[b[i], 0x0b] ^ mt[b[i + 4], 0x0d] ^ mt[b[i + 8], 0x09] ^ mt[b[i + 12], 0x0e]
            # fmt: on
            b[i], b[i + 4], b[i + 8], b[i + 12] = n0, n1, n2, n3

    @staticmethod
    def _add_round_key(block: bytearray) -> None:
        ...

    @staticmethod
    def _inverse_add_round_key(block: bytearray) -> None:
        ...


# TODO: Написать алгоритм генерации раундовых ключей
# TODO: Написать алгоритм _add_round_key
# TODO: Написать разбиение на блоки
# TODO: Написать алгоритм шифрования
# TODO: Написать алгоритм расшифрования
