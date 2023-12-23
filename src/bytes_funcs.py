def repack_bytes(block: bytes) -> bytes:
    return bytes(reversed(block))


def repack_bytearray(block: bytearray) -> None:
    block[:] = reversed(block)
