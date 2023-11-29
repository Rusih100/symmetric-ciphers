def left_cyclic_shift(number: int, shift: int, number_size: int) -> int:
    return ((number << shift) % (1 << number_size)) | (
        number >> (number_size - shift)
    )
