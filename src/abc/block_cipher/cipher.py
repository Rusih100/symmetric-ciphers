from abc import ABC, abstractmethod
from typing import Any, Literal

from src.abc.block_cipher.modes import (
    BlockCipherMode,
    ModeCBC,
    ModeCFB,
    ModeCTR,
    ModeECB,
    ModeOFB,
)
from src.ciphers.blocks import BlocksSinglePKCS7
from src.protocols import Blocks

CIPHER_MODES = Literal["ecb", "cbc", "cfb", "ofb", "ctr"]


class BlockCipher(ABC):
    _block_size: int = 0
    _key_size: int = 0
    _key_schedule: Any = None

    def __init__(
        self,
        cipher_key: bytes,
        cipher_mode: CIPHER_MODES = "ecb",
        init_vector: bytes | None = None,
        nonce: bytes | None = None,
        *,
        blocks_factory: Blocks = BlocksSinglePKCS7,
    ) -> None:
        assert isinstance(cipher_key, bytes)
        assert len(cipher_key) == self._key_size

        self._blocks_factory = blocks_factory

        self.init_vector = b""
        self.nonce = b""

        self._cipher_mode: BlockCipherMode

        match cipher_mode:
            case "ecb":
                self._cipher_mode = ModeECB(self)
            case "cbc":
                self._cipher_mode = ModeCBC(self, init_vector=init_vector)
            case "cfb":
                self._cipher_mode = ModeCFB(self, init_vector=init_vector)
            case "ofb":
                self._cipher_mode = ModeOFB(self, init_vector=init_vector)
            case "ctr":
                self._cipher_mode = ModeCTR(self, nonce=nonce)

        self._init_key_schedule(cipher_key)

    @property
    def block_size(self) -> int:
        return self._block_size

    @property
    def cipher_mode(self) -> str:
        return self._cipher_mode.mode

    def encrypt(self, data: bytes) -> bytes:
        blocks = self._blocks_factory.to_blocks(
            data, block_size=self._block_size, padding=True
        )
        self._cipher_mode.encrypt_blocks(blocks)

        return self._blocks_factory.from_blocks(blocks, padding=False)

    def decrypt(self, data: bytes) -> bytes:
        blocks = self._blocks_factory.to_blocks(
            data, block_size=self._block_size, padding=False
        )
        self._cipher_mode.decrypt_blocks(blocks)

        return self._blocks_factory.from_blocks(blocks, padding=True)

    @abstractmethod
    def _init_key_schedule(self, cipher_key: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def encrypt_block(self, block: bytearray) -> None:
        raise NotImplementedError

    @abstractmethod
    def decrypt_block(self, block: bytearray) -> None:
        raise NotImplementedError
