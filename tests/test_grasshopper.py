from copy import copy
from random import randbytes

import pytest

from src.ciphers import Grasshopper


class TestGrasshopper:
    @pytest.mark.parametrize(
        ("block", "expected_block"),
        [
            (
                bytearray.fromhex("ffeeddccbbaa99881122334455667700"),
                bytearray.fromhex("b66cd8887d38e8d77765aeea0c9a7efc"),
            ),
            (
                bytearray.fromhex("b66cd8887d38e8d77765aeea0c9a7efc"),
                bytearray.fromhex("559d8dd7bd06cbfe7e7b262523280d39"),
            ),
            (
                bytearray.fromhex("559d8dd7bd06cbfe7e7b262523280d39"),
                bytearray.fromhex("0c3322fed531e4630d80ef5c5a81c50b"),
            ),
            (
                bytearray.fromhex("0c3322fed531e4630d80ef5c5a81c50b"),
                bytearray.fromhex("23ae65633f842d29c5df529c13f5acda"),
            ),
        ],
    )
    def test_substitution(
        self, block: bytearray, expected_block: bytearray
    ) -> None:
        Grasshopper._substitution(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block",
        [
            # fmt: off
            bytearray(
                [0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08]
            ),
            *[bytearray(randbytes(16)) for _ in range(10)],
            # fmt: on
        ],
    )
    def test_inverse_substitution(self, block: bytearray) -> None:
        b = copy(block)
        Grasshopper._substitution(b)
        Grasshopper._inverse_substitution(b)
        assert b == block

    @pytest.mark.parametrize(
        ("block", "expected_block"),
        [
            (
                bytearray.fromhex("00000000000000000000000000000100"),
                bytearray.fromhex("94000000000000000000000000000001"),
            ),
            (
                bytearray.fromhex("94000000000000000000000000000001"),
                bytearray.fromhex("a5940000000000000000000000000000"),
            ),
            (
                bytearray.fromhex("a5940000000000000000000000000000"),
                bytearray.fromhex("64a59400000000000000000000000000"),
            ),
            (
                bytearray.fromhex("64a59400000000000000000000000000"),
                bytearray.fromhex("0d64a594000000000000000000000000"),
            ),
        ],
    )
    def test_rotate(self, block: bytearray, expected_block: bytearray) -> None:
        Grasshopper._rotate(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block",
        [
            # fmt: off
            bytearray(
                [0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08]
            ),
            *[bytearray(randbytes(16)) for _ in range(10)],
            # fmt: on
        ],
    )
    def test_inverse_rotate(self, block: bytearray) -> None:
        b = copy(block)
        Grasshopper._rotate(b)
        Grasshopper._inverse_rotate(b)
        assert b == block

    @pytest.mark.parametrize(
        ("block", "expected_block"),
        [
            (
                bytearray.fromhex("64a59400000000000000000000000000"),
                bytearray.fromhex("d456584dd0e3e84cc3166e4b7fa2890d"),
            ),
            (
                bytearray.fromhex("d456584dd0e3e84cc3166e4b7fa2890d"),
                bytearray.fromhex("79d26221b87b584cd42fbc4ffea5de9a"),
            ),
            (
                bytearray.fromhex("79d26221b87b584cd42fbc4ffea5de9a"),
                bytearray.fromhex("0e93691a0cfc60408b7b68f66b513c13"),
            ),
            (
                bytearray.fromhex("0e93691a0cfc60408b7b68f66b513c13"),
                bytearray.fromhex("e6a8094fee0aa204fd97bcb0b44b8580"),
            ),
        ],
    )
    def test_linear(self, block: bytearray, expected_block: bytearray) -> None:
        Grasshopper._linear(block)
        assert block == expected_block

    @pytest.mark.parametrize(
        "block",
        [
            # fmt: off
            bytearray(
                [0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08]
            ),
            *[bytearray(randbytes(16)) for _ in range(10)],
            # fmt: on
        ],
    )
    def test_inverse_linear(self, block: bytearray) -> None:
        b = copy(block)
        Grasshopper._linear(b)
        Grasshopper._inverse_linear(b)
        assert b == block

    @pytest.mark.parametrize(
        ("key", "expected_key_schedule"),
        [
            (
                bytes.fromhex(
                    "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
                )[::-1],
                [
                    bytearray.fromhex("8899aabbccddeeff0011223344556677"),
                    bytearray.fromhex("fedcba98765432100123456789abcdef"),
                    bytearray.fromhex("db31485315694343228d6aef8cc78c44"),
                    bytearray.fromhex("3d4553d8e9cfec6815ebadc40a9ffd04"),
                    bytearray.fromhex("57646468c44a5e28d3e59246f429f1ac"),
                    bytearray.fromhex("bd079435165c6432b532e82834da581b"),
                    bytearray.fromhex("51e640757e8745de705727265a0098b1"),
                    bytearray.fromhex("5a7925017b9fdd3ed72a91a22286f984"),
                    bytearray.fromhex("bb44e25378c73123a5f32f73cdb6e517"),
                    bytearray.fromhex("72e9dd7416bcf45b755dbaa88e4a4043"),
                ],
            )
        ],
    )
    def test_init_key_schedule(
        self, key: bytes, expected_key_schedule: list[bytearray]
    ) -> None:
        gh = Grasshopper(cipher_key=key)
        assert gh._key_schedule == expected_key_schedule

    @pytest.mark.parametrize(
        ("key", "block", "expected_block"),
        [
            (
                bytes.fromhex(
                    "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
                )[::-1],
                bytearray.fromhex("1122334455667700ffeeddccbbaa9988")[::-1],
                bytearray.fromhex("7f679d90bebc24305a468d42b9d4edcd")[::-1],
            )
        ],
    )
    def test_encrypt_block(
        self, key: bytes, block: bytearray, expected_block: bytearray
    ) -> None:
        gh = Grasshopper(cipher_key=key)
        gh.encrypt_block(block)

        assert block == expected_block

    @pytest.mark.parametrize(
        ("key", "block"),
        [*[(randbytes(32), bytearray(randbytes(16))) for _ in range(10)]],
    )
    def test_decrypt_block(self, key: bytes, block: bytearray) -> None:
        b = copy(block)
        gh = Grasshopper(cipher_key=key)
        gh.encrypt_block(block)
        gh.decrypt_block(block)

        assert block == b
