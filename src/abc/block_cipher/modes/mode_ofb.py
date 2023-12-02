from __future__ import annotations

from random import randbytes
from typing import TYPE_CHECKING

from src.abc.block_cipher.modes.cipher_mode import BlockCipherMode

if TYPE_CHECKING:
    from src.abc import BlockCipher


class ModeOFB(BlockCipherMode):
    _mode = "ofb"

    def __init__(self, cipher: BlockCipher, init_vector: bytes | None) -> None:
        self._cipher = cipher

        if init_vector is None:
            self._cipher.init_vector = randbytes(self._cipher.block_size)
        else:
            self._cipher.init_vector = init_vector

    def encrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = bytearray(self._cipher.init_vector)

        for block in blocks:
            self._cipher.encrypt_block(last)

            for i, b in enumerate(block):
                block[i] = b ^ last[i]

    def decrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = bytearray(self._cipher.init_vector)

        for block in blocks:
            self._cipher.encrypt_block(last)

            for i, b in enumerate(block):
                block[i] = b ^ last[i]
