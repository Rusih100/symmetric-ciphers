from random import randbytes, randint

import pytest

from src.ciphers.blocks import BlocksSinglePKCS7


class TestBlocksSinglePKCS7:
    @pytest.mark.parametrize(
        ("data", "block_size"),
        [(randbytes(randint(2, 512)), randint(2, 64)) for _ in range(10)],
    )
    def test_block_length(self, data: bytes, block_size: int) -> None:
        blocks = BlocksSinglePKCS7.to_blocks(data, block_size, padding=True)
        assert len(blocks[0]) == block_size
