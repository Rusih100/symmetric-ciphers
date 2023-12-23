def left_cyclic_shift(number: int, shift: int, number_bits_size: int) -> int:
    return ((number << shift) % (1 << number_bits_size)) | (
        number >> (number_bits_size - shift)
    )
