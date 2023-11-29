from copy import copy
from random import randbytes

import pytest

from src.ciphers import DES


class TestDES:
    @pytest.mark.parametrize(
        ("block", "expected_block"),
        [(bytearray(b'\x11"3DUfw\x88'), bytearray(b"xUxU\x80f\x80f"))],
    )
    def test_initial_permutation_reversibility(
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
