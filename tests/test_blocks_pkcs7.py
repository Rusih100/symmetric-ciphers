from random import randbytes, randint

import pytest

from src.ciphers.blocks import BlocksPKCS7


class TestBlocksPKCS7:
    @pytest.mark.parametrize(
        ("data", "block_size"),
        [(randbytes(randint(2, 512)), randint(2, 64)) for _ in range(20)],
    )
    def test_block_length(self, data: bytes, block_size: int) -> None:
        blocks = BlocksPKCS7.to_blocks(data, block_size, padding=True)
        assert len(blocks[0]) == block_size