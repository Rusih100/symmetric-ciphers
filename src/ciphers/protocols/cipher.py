from abc import abstractmethod
from typing import Protocol


class Cipher(Protocol):
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        raise NotImplementedError
