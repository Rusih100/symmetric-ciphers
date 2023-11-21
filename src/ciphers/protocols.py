from abc import abstractmethod
from typing import Protocol


class Cipher(Protocol):
    @abstractmethod
    def encode(self, data: bytes) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def decode(self, data: bytes) -> bytes:
        raise NotImplementedError
