from copy import copy

import pytest

from src.ciphers import AES128


class TestAES128:
    @pytest.mark.parametrize(
        ("block", "expected_block"),
        [
            # fmt: off
            (
                bytearray(
                    [0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08]
                ),
                bytearray(
                    [0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30]
                ),
            )
            # fmt: on
        ],
    )
    def test_sub_bytes(
        self, block: bytearray, expected_block: bytearray
    ) -> None:
        AES128._sub_bytes(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block",
        [
            # fmt: off
            bytearray(
                [0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08]
            )
            # fmt: on
        ],
    )
    def test_inverse_sub_bytes(self, block: bytearray) -> None:
        b = copy(block)
        AES128._sub_bytes(b)
        AES128._inverse_sub_bytes(b)
        assert b == block

    @pytest.mark.parametrize(
        ("block", "expected_block"),
        [
            # fmt: off
            (
                bytearray(
                    [0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30]
                ),
                bytearray(
                    [0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5]
                ),
            )
            # fmt: on
        ],
    )
    def test_shift_rows(
        self, block: bytearray, expected_block: bytearray
    ) -> None:
        AES128._shift_rows(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block",
        [
            # fmt: off
            bytearray(
                [0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30]
            )
            # fmt: on
        ],
    )
    def test_inverse_shift_rows(self, block: bytearray) -> None:
        b = copy(block)
        AES128._shift_rows(b)
        AES128._inverse_shift_rows(b)
        assert b == block

    @pytest.mark.parametrize(
        ("block", "expected_block"),
        [
            # fmt: off
            (
                bytearray(
                    [0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5]
                ),
                bytearray(
                    [0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c]
                ),
            )
            # fmt: on
        ],
    )
    def test_mix_column(
        self, block: bytearray, expected_block: bytearray
    ) -> None:
        AES128._mix_column(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block",
        [
            # fmt: off
            bytearray(
                [0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5]
            )
            # fmt: on
        ],
    )
    def test_inverse_mix_column(self, block: bytearray) -> None:
        b = copy(block)
        AES128._mix_column(b)
        AES128._inverse_mix_column(b)
        assert b == block

    @pytest.mark.parametrize(
        ("key", "expected_key_schedule"),
        [
            # fmt: off
            (
                b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                bytearray(
                    [
                        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                        0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05,
                        0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f
                    ]
                )
            )
            # fmt: on
        ],
    )
    def test_key_expansion(  # Тестирует первые 2 раунда
        self, key: bytes, expected_key_schedule: bytearray
    ) -> None:
        aes = AES128(cipher_key=key)
        assert aes._key_schedule[: 3 * 16] == expected_key_schedule
