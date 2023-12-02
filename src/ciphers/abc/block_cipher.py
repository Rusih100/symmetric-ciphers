from abc import ABC, abstractmethod
from copy import copy
from random import randbytes
from typing import Any, Final, Literal

from src.ciphers.blocks import BlocksSinglePKCS7
from src.protocols import Blocks

ECB: Final = "ecb"
CBC: Final = "cbc"
CFB: Final = "cfb"
OFB: Final = "ofb"
CTR: Final = "ctr"

CIPHER_MODES = Literal["ecb", "cbc", "cfb", "ofb", "ctr"]


class BlockCipher(ABC):
    _block_size: int = 0
    _key_size: int = 0
    _key_schedule: Any = None

    def __init__(
        self,
        cipher_key: bytes,
        cipher_mode: CIPHER_MODES = ECB,
        init_vector: bytes | None = None,
        nonce: bytes | None = None,
        *,
        blocks_factory: Blocks = BlocksSinglePKCS7,
    ) -> None:
        assert isinstance(cipher_key, bytes)
        assert len(cipher_key) == self._key_size

        self._blocks_factory = blocks_factory
        self._cipher_mode = cipher_mode

        if init_vector is None:
            match self._cipher_mode:
                case "ecb" | "ctr":
                    self._init_vector = b""
                case "cbc" | "cfb" | "ofb":
                    self._init_vector = randbytes(self._block_size)
        else:
            assert isinstance(init_vector, bytes)
            assert len(init_vector) == self._block_size
            self._init_vector = init_vector

        if nonce is None:
            match self._cipher_mode:
                case "ctr":
                    self._nonce = randbytes(self._block_size // 2)
                case "ecb" | "cbc" | "cfb" | "ofb":
                    self._nonce = b""
        else:
            assert isinstance(nonce, bytes)
            assert len(nonce) * 2 == self._block_size
            self._nonce = nonce

        self._init_key_schedule(cipher_key)

    @property
    def init_vector(self) -> bytes:
        return self._init_vector

    @property
    def nonce(self) -> bytes:
        return self._nonce

    @property
    def cipher_mode(self) -> str:
        return self._cipher_mode

    def encrypt(self, data: bytes) -> bytes:
        blocks = self._blocks_factory.to_blocks(
            data, block_size=self._block_size, padding=True
        )
        match self._cipher_mode:  # Где-то грустит абстрактная фабрика
            case "ecb":
                self._ecb_encrypt_blocks(blocks)
            case "cbc":
                self._cbc_encrypt_blocks(blocks)
            case "cfb":
                self._cfb_encrypt_blocks(blocks)
            case "ofb":
                self._ofb_encrypt_blocks(blocks)
            case "ctr":
                self._ctr_encrypt_blocks(blocks)
            case _:
                return b""

        return self._blocks_factory.from_blocks(blocks, padding=False)

    def decrypt(self, data: bytes) -> bytes:
        blocks = self._blocks_factory.to_blocks(
            data, block_size=self._block_size, padding=False
        )
        match self._cipher_mode:
            case "ecb":
                self._ecb_decrypt_blocks(blocks)
            case "cbc":
                self._cbc_decrypt_blocks(blocks)
            case "cfb":
                self._cfb_decrypt_blocks(blocks)
            case "ofb":
                self._ofb_decrypt_blocks(blocks)
            case "ctr":
                self._ctr_decrypt_blocks(blocks)
            case _:
                return b""

        return self._blocks_factory.from_blocks(blocks, padding=True)

    def _ecb_encrypt_blocks(self, blocks: list[bytearray]) -> None:
        for block in blocks:
            self._encrypt_block(block)

    def _ecb_decrypt_blocks(self, blocks: list[bytearray]) -> None:
        for block in blocks:
            self._decrypt_block(block)

    def _cbc_encrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = self._init_vector

        for block in blocks:
            for i, b in enumerate(block):
                block[i] = b ^ last[i]

            self._encrypt_block(block)
            last = block

    def _cbc_decrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = self._init_vector

        for block in blocks:
            new_last = copy(block)
            self._decrypt_block(block)

            for i, b in enumerate(block):
                block[i] = b ^ last[i]

            last = new_last

    def _cfb_encrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = bytearray(self._init_vector)

        for block in blocks:
            self._encrypt_block(last)

            for i, b in enumerate(block):
                block[i] = b ^ last[i]

            last = copy(block)

    def _cfb_decrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = bytearray(self._init_vector)

        for block in blocks:
            self._encrypt_block(last)

            new_last = copy(block)
            for i, b in enumerate(block):
                block[i] = b ^ last[i]

            last = new_last

    def _ofb_encrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = bytearray(self._init_vector)

        for block in blocks:
            self._encrypt_block(last)

            for i, b in enumerate(block):
                block[i] = b ^ last[i]

    def _ofb_decrypt_blocks(self, blocks: list[bytearray]) -> None:
        last = bytearray(self._init_vector)

        for block in blocks:
            self._encrypt_block(last)

            for i, b in enumerate(block):
                block[i] = b ^ last[i]

    def _ctr_encrypt_blocks(self, blocks: list[bytearray]) -> None:
        counter = int.from_bytes(
            self._nonce + b"\x00" * (self._block_size // 2), byteorder="big"
        )
        for block in blocks:
            counter_bytes = bytearray(
                counter.to_bytes(self._block_size, byteorder="big")
            )
            self._encrypt_block(counter_bytes)

            for i, b in enumerate(block):
                block[i] = b ^ counter_bytes[i]

            counter += 1

    def _ctr_decrypt_blocks(self, blocks: list[bytearray]) -> None:
        counter = int.from_bytes(
            self._nonce + b"\x00" * (self._block_size // 2), byteorder="big"
        )
        for block in blocks:
            counter_bytes = bytearray(
                counter.to_bytes(self._block_size, byteorder="big")
            )
            self._encrypt_block(counter_bytes)

            for i, b in enumerate(block):
                block[i] = b ^ counter_bytes[i]

            counter += 1

    @abstractmethod
    def _init_key_schedule(self, cipher_key: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def _encrypt_block(self, block: bytearray) -> None:
        raise NotImplementedError

    @abstractmethod
    def _decrypt_block(self, block: bytearray) -> None:
        raise NotImplementedError
