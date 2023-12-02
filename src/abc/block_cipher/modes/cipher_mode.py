from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.abc import BlockCipher


class BlockCipherMode(ABC):
    _mode = ""

    @abstractmethod
    def __init__(self, cipher: BlockCipher, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError

    @abstractmethod
    def encrypt_blocks(self, blocks: list[bytearray]) -> None:
        raise NotImplementedError

    @abstractmethod
    def decrypt_blocks(self, blocks: list[bytearray]) -> None:
        raise NotImplementedError

    @property
    def mode(self) -> str:
        return self._mode
