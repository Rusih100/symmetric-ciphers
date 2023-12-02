from random import randbytes, randint

import pytest
from Crypto.Cipher import AES as LibAES
from Crypto.Util.Padding import pad

from src.ciphers import AES
from src.ciphers.cipher_modes import CBC, CFB, CTR, ECB, OFB


class TestECBCipherMode:
    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_encrypt(self, key: bytes, message: bytes) -> None:
        aes_lib = LibAES.new(key, LibAES.MODE_ECB)
        message_lib = pad(message, 16)

        aes = AES(cipher_key=key, cipher_mode=ECB)
        assert aes_lib.encrypt(message_lib) == aes.encrypt(message)

    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_decrypt(self, key: bytes, message: bytes) -> None:
        aes = AES(cipher_key=key, cipher_mode=ECB)
        encrypt_message = aes.encrypt(message)
        assert aes.decrypt(encrypt_message) == message


class TestCBCCipherMode:
    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_encrypt(self, key: bytes, message: bytes) -> None:
        aes_lib = LibAES.new(key, LibAES.MODE_CBC)
        message_lib = pad(message, 16)

        aes = AES(cipher_key=key, cipher_mode=CBC, init_vector=aes_lib.iv)
        assert aes_lib.encrypt(message_lib) == aes.encrypt(message)

    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_decrypt(self, key: bytes, message: bytes) -> None:
        aes = AES(cipher_key=key, cipher_mode=CBC)
        encrypt_message = aes.encrypt(message)
        assert aes.decrypt(encrypt_message) == message


class TestCFBCipherMode:
    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_encrypt(self, key: bytes, message: bytes) -> None:
        aes_lib = LibAES.new(key, LibAES.MODE_CFB, segment_size=8 * 16)
        message_lib = pad(message, 16)

        aes = AES(cipher_key=key, cipher_mode=CFB, init_vector=aes_lib.iv)
        assert aes_lib.encrypt(message_lib) == aes.encrypt(message)

    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_decrypt(self, key: bytes, message: bytes) -> None:
        aes = AES(cipher_key=key, cipher_mode=CFB)
        encrypt_message = aes.encrypt(message)
        assert aes.decrypt(encrypt_message) == message


class TestOFBCipherMode:
    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_encrypt(self, key: bytes, message: bytes) -> None:
        aes_lib = LibAES.new(key, LibAES.MODE_OFB)
        message_lib = pad(message, 16)

        aes = AES(cipher_key=key, cipher_mode=OFB, init_vector=aes_lib.iv)
        assert aes_lib.encrypt(message_lib) == aes.encrypt(message)

    @pytest.mark.parametrize(
        ("key", "message"),
        [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
    )
    def test_decrypt(self, key: bytes, message: bytes) -> None:
        aes = AES(cipher_key=key, cipher_mode=OFB)
        encrypt_message = aes.encrypt(message)
        assert aes.decrypt(encrypt_message) == message

    class TestCTRCipherMode:
        @pytest.mark.parametrize(
            ("key", "message"),
            [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
        )
        def test_encrypt(self, key: bytes, message: bytes) -> None:
            aes_lib = LibAES.new(key, LibAES.MODE_CTR)
            message_lib = pad(message, 16)

            aes = AES(cipher_key=key, cipher_mode=CTR, nonce=aes_lib.nonce)
            assert aes_lib.encrypt(message_lib) == aes.encrypt(message)

        @pytest.mark.parametrize(
            ("key", "message"),
            [*[(randbytes(16), randbytes(randint(1, 256))) for _ in range(10)]],
        )
        def test_decrypt(self, key: bytes, message: bytes) -> None:
            aes = AES(cipher_key=key, cipher_mode=CTR)
            encrypt_message = aes.encrypt(message)
            assert aes.decrypt(encrypt_message) == message
