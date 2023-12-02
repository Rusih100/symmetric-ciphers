from __future__ import annotations

from typing import TYPE_CHECKING

from src.abc.block_cipher.modes.cipher_mode import BlockCipherMode

if TYPE_CHECKING:
    from src.abc import BlockCipher


class ModeECB(BlockCipherMode):
    _mode = "ecb"

    def __init__(self, cipher: BlockCipher) -> None:
        self._cipher = cipher

    def encrypt_blocks(self, blocks: list[bytearray]) -> None:
        for block in blocks:
            self._cipher.encrypt_block(block)

    def decrypt_blocks(self, blocks: list[bytearray]) -> None:
        for block in blocks:
            self._cipher.decrypt_block(block)
