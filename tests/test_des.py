from copy import copy
from random import randbytes, randint

import pytest
from Crypto.Cipher import DES as LibDES
from Crypto.Util.Padding import pad

from src.ciphers import DES


class TestDES:
    @pytest.mark.parametrize(
        ("block", "expected_block"),
        [(bytearray(b'\x11"3DUfw\x88'), bytearray(b"xUxU\x80f\x80f"))],
    )
    def test_initial_permutation(
        self, block: bytearray, expected_block: bytearray
    ) -> None:
        DES._initial_permutation(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block", [bytearray(randbytes(8)) for i in range(10)]
    )
    def test_initial_permutation_reversibility(self, block: bytearray) -> None:
        b = copy(block)
        DES._initial_permutation(block)
        DES._inverse_initial_permutation(block)
        assert b == block

    @pytest.mark.parametrize(
        ("bits", "expected_bits"),
        [
            (
                0xFC00D0D8,
                0b011111111000000000000001011010100001011011110001,
            ),
            (
                0b10000000011001101000000001100110,
                0b010000000000001100001101010000000000001100001101,
            ),
        ],
    )
    def test_expansion(self, bits: int, expected_bits: int) -> None:
        assert DES._expansion(bits) == expected_bits

    @pytest.mark.parametrize(
        ("bits", "expected_bits"),
        [
            (
                0b010101001001001101000000011100110101011011110001,
                0b11001111011001111110000111111111,
            ),
            (
                0b011110001010111111100010000001100101010101000111,
                0b01111011110001101110001001011000,
            ),
        ],
    )
    def test_substitution(self, bits: int, expected_bits: int) -> None:
        assert DES._substitution(bits) == expected_bits

    @pytest.mark.parametrize(
        ("bits", "expected_bits"),
        [
            (
                0b11001111011001111110000111111111,
                0b11001011110111111111110010110101,
            ),
            (
                0b01111011110001101110001001011000,
                0b01001011011111011101001110000010,
            ),
        ],
    )
    def test_permutation(self, bits: int, expected_bits: int) -> None:
        assert DES._permutation(bits) == expected_bits

    @pytest.mark.parametrize(
        ("bits", "expected_bits"),
        [
            (
                0b0111010100101000011110000011100101110100100100111100101101110000,
                0b01100000110101011001111110110110000000010001010011101101,
            )
        ],
    )
    def test_key_permutation(self, bits: int, expected_bits: int) -> None:
        assert DES._key_permutation(bits) == expected_bits

    @pytest.mark.parametrize(
        (
            "bits",
            "expected_bits",
            "offset",
        ),
        [
            (
                0b01100000110101011001111110110110000000010001010011101101,
                0b11000001101010110011111101101100000000100010100111011010,
                1,
            )
        ],
    )
    def test_rotate_key(
        self,
        bits: int,
        expected_bits: int,
        offset: int,
    ) -> None:
        assert DES._key_rotate(bits, offset) == expected_bits

    @pytest.mark.parametrize(
        ("bits", "expected_bits"),
        [
            (
                0b11000001101010110011111101101100000000100010100111011010,
                0b001110001010110011101111010001100101011001001010,
            )
        ],
    )
    def test_key_expansion(self, bits: int, expected_bits: int) -> None:
        assert DES._key_expansion(bits) == expected_bits

    @pytest.mark.parametrize(
        ("key", "expected_schedule"),
        [
            (
                b"\x75\x28\x78\x39\x74\x93\xCB\x70",
                [
                    0b001110001010110011101111010001100101011001001010,
                    0b100010011011111011010100010010001001110100010010,
                    0b010101000111111011101110010011010100010000111100,
                    0b111100101111010101100000010010010101100011001000,
                    0b110010001100111101100111100000001101000000111101,
                    0b111000011111001100011111100000110001111010100100,
                    0b001001011001011111100011100110000000101110110001,
                    0b111100110101100011110011000100110100101000010101,
                    0b000011001101101001111011101000000000101011000110,
                    0b101001110111100101011110100101001010001010010111,
                    0b001011100110111111000001001101110000011011000001,
                    0b010110110111110100111001000110101010000101000011,
                    0b110011011010010111011001001001101110010100000100,
                    0b010101111100111010001111011010000010010111000010,
                    0b011110111011100110000010111011001100000000001011,
                    0b110100110011101000101101001000111000110101101000,
                ],
            )
        ],
    )
    def test_init_key_schedule(
        self, key: bytes, expected_schedule: list[int]
    ) -> None:
        des = DES(key)
        assert len(des._key_schedule) == 16
        assert des._key_schedule == expected_schedule

    @pytest.mark.parametrize(
        ("bits", "key", "expected_bits"),
        [
            (
                0b10000000011001101000000001100110,
                0b001110001010110011101111010001100101011001001010,
                0b01001011011111011101001110000010,
            )
        ],
    )
    def test_feistel_function(
        self, bits: int, key: int, expected_bits: int
    ) -> None:
        assert DES._feistel_function(bits, key) == expected_bits

    @pytest.mark.parametrize(
        ("key", "block", "expected_block"),
        [
            # fmt: off
            (
                b"\x75\x28\x78\x39\x74\x93\xCB\x70",
                bytearray(
                    b"\x11\x22\x33\x44\x55\x66\x77\x88"
                ),
                bytearray(
                    b"\xB5\x21\x9E\xE8\x1A\xA7\x49\x9D"
                )
            )
            # fmt: on
        ],
    )
    def test_encrypt_block(
        self, key: bytes, block: bytearray, expected_block: bytearray
    ) -> None:
        des = DES(cipher_key=key)
        des._encrypt_block(block)

        assert block == expected_block

    @pytest.mark.parametrize(
        ("key", "block"),
        [
            # fmt: off
            *[
                (
                    randbytes(8),
                    bytearray(randbytes(8))
                ) for _ in range(10)
            ]
            # fmt: on
        ],
    )
    def test_decrypt_block(self, key: bytes, block: bytearray) -> None:
        b = copy(block)
        des = DES(cipher_key=key)
        des._encrypt_block(block)
        des._decrypt_block(block)

        assert block == b

    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(8), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_lib_des(self, key: bytes, message: bytes) -> None:
        des_lib = LibDES.new(key, LibDES.MODE_ECB)
        message_lib = pad(message, 8)

        des = DES(cipher_key=key)
        assert des_lib.encrypt(message_lib) == des.encrypt(message)
