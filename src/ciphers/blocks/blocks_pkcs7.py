from math import ceil


class BlocksPKCS7:
    @classmethod
    def to_blocks(
        cls, data: bytes, block_size: int, *, padding: bool
    ) -> list[bytearray]:
        if not padding:
            block_size = block_size + 1
        blocks = cls._bytes_to_blocks(data, block_size - 1)
        if padding:
            for block in blocks:
                cls._add_padding(block, block_size)
        return blocks

    @classmethod
    def from_blocks(cls, blocks: list[bytearray], *, padding: bool) -> bytes:
        if padding:
            for block in blocks:
                cls._del_padding(block)
        return cls._blocks_to_bytes(blocks)

    @staticmethod
    def _bytes_to_blocks(data_bytes: bytes, block_size: int) -> list[bytearray]:
        blocks: list[bytearray] = []
        block_count = ceil(len(data_bytes) / block_size)

        for i in range(block_count):
            block = bytearray(data_bytes[i * block_size : (i + 1) * block_size])
            blocks.append(block)
        return blocks

    @staticmethod
    def _blocks_to_bytes(blocks: list[bytearray]) -> bytes:
        data_bytes = bytearray()
        for block in blocks:
            data_bytes += block
        return bytes(data_bytes)

    @staticmethod
    def _add_padding(block: bytearray, block_size: int) -> None:
        count = block_size - len(block)
        if count <= 0:
            raise ValueError(
                "The number of padded bytes must be greater than 0"
            )

        value = count.to_bytes(1, byteorder="big")
        for _ in range(count):
            block += value

    @staticmethod
    def _del_padding(block: bytearray) -> None:
        count = block[-1]

        for _ in range(count):
            b = block.pop()
            if b != count:
                raise ValueError(
                    "The transmitted byte sequence does not contain padding"
                )
