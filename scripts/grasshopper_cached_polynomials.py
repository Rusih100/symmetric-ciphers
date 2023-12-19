from src.polynomial import Polynomial


def int_to_poly(n: int) -> Polynomial:
    bin_poly: str = bin(n)[2:]
    coefficients: list[int] = list(map(int, list(bin_poly)))[::-1]
    return Polynomial(coefficients)


def to_num(polynomial: Polynomial) -> int:
    coefficients = list(map(str, polynomial.coefficients))[::-1]
    return int("".join(coefficients), 2)


mul_table: dict[tuple[int, int], int] = {}

polynomials = (
    int_to_poly(1),
    int_to_poly(16),
    int_to_poly(32),
    int_to_poly(133),
    int_to_poly(148),
    int_to_poly(192),
    int_to_poly(194),
    int_to_poly(251),
)
mod = Polynomial(1, 1, 0, 0, 0, 0, 1, 1, 1)
print(mod)

for num in range(256):
    poly = int_to_poly(num)

    for p in polynomials:
        mul_table[(to_num(poly), to_num(p))] = to_num(((poly * p) % mod).mod(2))


for i, ((k1, k2), v) in enumerate(mul_table.items()):
    if i % 4 == 0 and i != 0:
        print()
    print(f"(0x{k1:02x}, 0x{k2:02x}): 0x{v:02x}, ", end="")
