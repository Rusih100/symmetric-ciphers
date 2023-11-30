from abc import ABC, abstractmethod
from typing import Any, Final, Literal

from src.ciphers.blocks import BlocksSinglePKCS7
from src.protocols import Blocks

ECB: Final = "ecb"
CBC: Final = "cbc"
CFB: Final = "cfb"
OFB: Final = "ofb"
CTR: Final = "ctr"

CIPHER_MODE = Literal["ecb", "cbc", "cfb", "ofb", "ctr"]


class BlockCipher(ABC):
    _block_size: int = 0
    _key_size: int = 0
    _key_schedule: Any = None

    def __init__(
        self,
        cipher_key: bytes,
        cipher_mode: CIPHER_MODE = ECB,
        *,
        blocks_class: Blocks = BlocksSinglePKCS7,
    ) -> None:
        assert isinstance(cipher_key, bytes)
        assert len(cipher_key) == self._key_size

        self._blocks_class = blocks_class
        self._cipher_mode = cipher_mode
        self._init_key_schedule(cipher_key)

    def encrypt(self, data: bytes) -> bytes:
        blocks = self._blocks_class.to_blocks(
            data, block_size=self._block_size, padding=True
        )
        match self._cipher_mode:
            case "ecb":
                self._ecb_encrypt_blocks(blocks)

        return self._blocks_class.from_blocks(blocks, padding=False)

    def decrypt(self, data: bytes) -> bytes:
        blocks = self._blocks_class.to_blocks(
            data, block_size=self._block_size, padding=False
        )
        match self._cipher_mode:
            case "ecb":
                self._ecb_decrypt_blocks(blocks)

        return self._blocks_class.from_blocks(blocks, padding=True)

    def _ecb_encrypt_blocks(self, blocks: list[bytearray]) -> None:
        for block in blocks:
            self._encrypt_block(block)

    def _ecb_decrypt_blocks(self, blocks: list[bytearray]) -> None:
        for block in blocks:
            self._decrypt_block(block)

    @abstractmethod
    def _init_key_schedule(self, cipher_key: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def _encrypt_block(self, block: bytearray) -> None:
        raise NotImplementedError

    @abstractmethod
    def _decrypt_block(self, block: bytearray) -> None:
        raise NotImplementedError
