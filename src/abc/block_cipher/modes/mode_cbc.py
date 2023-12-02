from __future__ import annotations

from copy import copy
from random import randbytes
from typing import TYPE_CHECKING

from src.abc.block_cipher.modes.cipher_mode import BlockCipherMode

if TYPE_CHECKING:
    from src.abc import BlockCipher


class ModeCBC(BlockCipherMode):
    _mode = "cbc"

    def __init__(self, cipher: BlockCipher, init_vector: bytes | None) -> None:
        self._cipher = cipher

        if init_vector is None:
            self._cipher.init_vector = randbytes(self._cipher.block_size)
        else:
            self._cipher.init_vector = init_vector

    def encrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = self._cipher.init_vector

        for block in blocks:
            for i, b in enumerate(block):
                block[i] = b ^ last[i]

            self._cipher.encrypt_block(block)
            last = block

    def decrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = self._cipher.init_vector

        for block in blocks:
            new_last = copy(block)
            self._cipher.decrypt_block(block)

            for i, b in enumerate(block):
                block[i] = b ^ last[i]

            last = new_last
