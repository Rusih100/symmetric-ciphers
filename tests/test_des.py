from copy import copy
from random import randbytes

import pytest

from src.ciphers import DES


class TestDES:
    @pytest.mark.parametrize(
        "block", [bytearray(randbytes(8)) for i in range(10)]
    )
    def test_initial_permutation(self, block: bytearray) -> None:
        b = copy(block)
        DES._initial_permutation(block)
        DES._inverse_initial_permutation(block)
        assert b == block
