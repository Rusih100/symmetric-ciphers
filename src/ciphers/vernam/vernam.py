from typing import Final


class Vernam:
    def __init__(self, gamma: bytes, *, mod: int = 256) -> None:
        self.gamma = gamma
        self._MOD: Final[int] = mod

    def encrypt(self, data: bytes) -> bytes:
        encoded: list[int] = []

        for i, m in enumerate(data):
            c = (m + self.gamma[i % len(self.gamma)]) % self._MOD
            encoded.append(c)
        return bytes(encoded)

    def decrypt(self, data: bytes) -> bytes:
        decoded: list[int] = []

        for i, c in enumerate(data):
            m = (c - self.gamma[i % len(self.gamma)] + self._MOD) % self._MOD
            decoded.append(m)
        return bytes(decoded)
