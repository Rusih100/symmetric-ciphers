from abc import abstractmethod
from typing import Protocol


class Blocks(Protocol):
    @classmethod
    @abstractmethod
    def to_blocks(
        cls, data: bytes, block_size: int, *, padding: bool
    ) -> list[bytearray]:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_blocks(cls, blocks: list[bytearray], *, padding: bool) -> bytes:
        raise NotImplementedError
