from copy import copy
from random import randbytes, randint

import pytest
from Crypto.Cipher import AES as LibAES
from Crypto.Util.Padding import pad

from src.ciphers import AES


class TestAES:
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
        AES._sub_bytes(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block",
        [
            # fmt: off
            bytearray(
                [0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08]
            ),
            *[bytearray(randbytes(16)) for _ in range(10)],
            # fmt: on
        ],
    )
    def test_inverse_sub_bytes(self, block: bytearray) -> None:
        b = copy(block)
        AES._sub_bytes(b)
        AES._inverse_sub_bytes(b)
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
        AES._shift_rows(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block",
        [
            # fmt: off
            bytearray(
                [0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30]
            ),
            *[bytearray(randbytes(16)) for _ in range(10)]
            # fmt: on
        ],
    )
    def test_inverse_shift_rows(self, block: bytearray) -> None:
        b = copy(block)
        AES._shift_rows(b)
        AES._inverse_shift_rows(b)
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
        AES._mix_column(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block",
        [
            # fmt: off
            bytearray(
                [0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5]
            ),
            *[bytearray(randbytes(16)) for _ in range(10)],
            # fmt: on
        ],
    )
    def test_inverse_mix_column(self, block: bytearray) -> None:
        b = copy(block)
        AES._mix_column(b)
        AES._inverse_mix_column(b)
        assert b == block

    @pytest.mark.parametrize(
        ("key", "block", "expected_block"),
        [
            # fmt: off
            (
                b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                bytearray(
                    [0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c]
                ),
                bytearray(
                    [0xa4, 0x9c, 0x7f, 0xf2, 0x68, 0x9f, 0x35, 0x2b, 0x6b, 0x5b, 0xea, 0x43, 0x02, 0x6a, 0x50, 0x49]
                )
            )
            # fmt: on
        ],
    )
    def test_add_round_key(
        self,
        key: bytes,
        block: bytearray,
        expected_block: bytearray,
    ) -> None:
        aes = AES(cipher_key=key)
        aes._add_round_key(block, 1)
        assert block == expected_block

    @pytest.mark.parametrize(
        ("key", "block"),
        [
            # fmt: off
            (
                b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                bytearray(
                    [0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c]
                ),
            ),
            *[
                (
                    randbytes(16),
                    bytearray(randbytes(16))
                ) for _ in range(10)
            ]
            # fmt: on
        ],
    )
    def test_inverse_add_round_key(
        self,
        key: bytes,
        block: bytearray,
    ) -> None:
        b = copy(block)
        aes = AES(cipher_key=key)
        aes._add_round_key(block, 1)
        aes._inverse_add_round_key(block, 1)
        assert block == b

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
                        0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f,
                        0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b,
                        0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00,
                        0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc,
                        0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd,
                        0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f,
                        0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f,
                        0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e,
                        0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6,
                    ]
                )
            )
            # fmt: on
        ],
    )
    def test_key_expansion(
        self, key: bytes, expected_key_schedule: bytearray
    ) -> None:
        aes = AES(cipher_key=key)
        assert aes._key_schedule == expected_key_schedule

    @pytest.mark.parametrize(
        ("key", "block", "expected_block"),
        [
            # fmt: off
            (
                b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                bytearray(
                    [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
                ),
                bytearray(
                    [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]
                )
            )
            # fmt: on
        ],
    )
    def test_encrypt_block(
        self, key: bytes, block: bytearray, expected_block: bytearray
    ) -> None:
        aes = AES(cipher_key=key)
        aes.encrypt_block(block)

        assert block == expected_block

    @pytest.mark.parametrize(
        ("key", "block"),
        [
            # fmt: off
            (
                b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                bytearray(
                    [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
                )
            ),
            *[
                (
                    randbytes(16),
                    bytearray(randbytes(16))
                ) for _ in range(10)
            ]
            # fmt: on
        ],
    )
    def test_decrypt_block(self, key: bytes, block: bytearray) -> None:
        b = copy(block)
        aes = AES(cipher_key=key)
        aes.encrypt_block(block)
        aes.decrypt_block(block)

        assert block == b

    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_lib_aes(self, key: bytes, message: bytes) -> None:
        aes_lib = LibAES.new(key, LibAES.MODE_ECB)
        message_lib = pad(message, 16)

        aes = AES(cipher_key=key)
        assert aes_lib.encrypt(message_lib) == aes.encrypt(message)
