from __future__ import annotations

from random import randbytes
from typing import TYPE_CHECKING

from src.abc.block_cipher.modes.cipher_mode import BlockCipherMode

if TYPE_CHECKING:
    from src.abc import BlockCipher


class ModeCTR(BlockCipherMode):
    _mode = "ctr"

    def __init__(self, cipher: BlockCipher, nonce: bytes | None) -> None:
        self._cipher = cipher

        if nonce is None:
            self._cipher.nonce = randbytes(self._cipher.block_size // 2)
        else:
            self._cipher.nonce = nonce

    def encrypt_blocks(self, blocks: list[bytearray]) -> None:
        counter = int.from_bytes(
            self._cipher.nonce + b"\x00" * (self._cipher.block_size // 2),
            byteorder="big",
        )
        for block in blocks:
            counter_bytes = bytearray(
                counter.to_bytes(self._cipher.block_size, byteorder="big")
            )
            self._cipher.encrypt_block(counter_bytes)

            for i, b in enumerate(block):
                block[i] = b ^ counter_bytes[i]

            counter += 1

    def decrypt_blocks(self, blocks: list[bytearray]) -> None:
        counter = int.from_bytes(
            self._cipher.nonce + b"\x00" * (self._cipher.block_size // 2),
            byteorder="big",
        )
        for block in blocks:
            counter_bytes = bytearray(
                counter.to_bytes(self._cipher.block_size, byteorder="big")
            )
            self._cipher.encrypt_block(counter_bytes)

            for i, b in enumerate(block):
                block[i] = b ^ counter_bytes[i]

            counter += 1
