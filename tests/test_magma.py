from copy import copy
from random import randbytes

import pytest

from src.ciphers import Magma


class TestMagma:
    @pytest.mark.parametrize(
        ("key", "expected_schedule"),
        [
            (
                bytes.fromhex(
                    "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                )[::-1],
                # fmt: off
                [
                    4293844428, 3148519816, 2003195204, 857870592, 4042388211, 4109760247, 4177132283, 4244504319,
                    4293844428, 3148519816, 2003195204, 857870592, 4042388211, 4109760247, 4177132283, 4244504319,
                    4293844428, 3148519816, 2003195204, 857870592, 4042388211, 4109760247, 4177132283, 4244504319,
                    4244504319, 4177132283, 4109760247, 4042388211, 857870592, 2003195204, 3148519816, 4293844428,
                ]
                # fmt: on
            )
        ],
    )
    def test_init_key_schedule(
        self, key: bytes, expected_schedule: list[int]
    ) -> None:
        magma = Magma(key)
        assert len(magma._key_schedule)
        print(magma._key_schedule)
        print(expected_schedule)
        assert magma._key_schedule == expected_schedule

    @pytest.mark.parametrize(
        ("bits", "expected_bits"),
        [
            (0xFDB97531, 0x2A196F34),
            (0x2A196F34, 0xEBD9F03A),
            (0xEBD9F03A, 0xB039BB3D),
            (0xB039BB3D, 0x68695433),
        ],
    )
    def test_t_function(self, bits: int, expected_bits: int) -> None:
        assert Magma._t_function(bits) == expected_bits

    @pytest.mark.parametrize(
        ("bits", "key_bits", "expected_bits"),
        [
            # fmt: off
            (0xfedcba98, 0x87654321, 0xfdcbc20c),
            (0x87654321, 0xfdcbc20c, 0x7e791a4b),
            (0xfdcbc20c, 0x7e791a4b, 0xc76549ec),
            (0x7e791a4b, 0xc76549ec, 0x9791c849),
            # fmt: on
        ],
    )
    def test_g_function(
        self, bits: int, key_bits: int, expected_bits: int
    ) -> None:
        assert Magma._g_function(bits, key_bits) == expected_bits

    @pytest.mark.parametrize(
        ("key", "block", "expected_block"),
        [
            (
                bytes.fromhex(
                    "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                )[::-1],
                bytearray.fromhex("fedcba9876543210")[::-1],
                bytearray.fromhex("4ee901e5c2d8ca3d")[::-1],
            )
        ],
    )
    def test_encrypt_block(
        self, key: bytes, block: bytearray, expected_block: bytearray
    ) -> None:
        magma = Magma(cipher_key=key)
        magma.encrypt_block(block)

        assert block == expected_block

    @pytest.mark.parametrize(
        ("key", "block"),
        [*[(randbytes(32), bytearray(randbytes(8))) for _ in range(10)]],
    )
    def test_decrypt_block(self, key: bytes, block: bytearray) -> None:
        b = copy(block)
        magma = Magma(cipher_key=key)
        magma.encrypt_block(block)
        magma.decrypt_block(block)

        assert block == b
