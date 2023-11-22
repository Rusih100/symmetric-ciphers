from __future__ import annotations

from copy import copy
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Generator

EPSILON = 1.0e-20


class Polynomial:
    def __init__(self, *coefficients: Any) -> None:
        self.coefficients: list[int | float] = []

        if isinstance(coefficients[0], dict):
            d = max(coefficients[0].keys())
            for k in range(d + 1):
                if k not in coefficients[0]:
                    self.coefficients.append(0)
                else:
                    self.coefficients.append(coefficients[0][k])
        elif isinstance(coefficients[0], list):
            self.coefficients = copy(coefficients[0])
        elif isinstance(coefficients[0], Polynomial):
            self.coefficients = copy(coefficients[0].coefficients)
        else:
            self.coefficients = list(coefficients)

        while (
            len(self.coefficients) > 0 and abs(self.coefficients[-1]) < EPSILON
        ):
            self.coefficients.pop()

        if len(self.coefficients) == 0:
            self.coefficients = [0]

    @property
    def d(self) -> int:
        return len(self.coefficients) - 1

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        s = ""
        if self.coefficients == [0]:
            return "0"
        for i, c in enumerate(self.coefficients[::-1]):
            k = self.d - i
            if c == 0:
                continue
            if c < 0:
                if len(s) > 0:
                    s += " - "
                else:
                    s += "-"
            elif len(s) > 0:
                s += " + "
            if abs(c) != 1 or k == 0:
                s += "%d" % abs(c)
            if k > 0:
                s += "x"
            if k > 1:
                s += "^%d" % k
        return s

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Polynomial):
            return False
        if self.d != other.d:
            return False
        for c1, c2 in zip(self.coefficients, other.coefficients, strict=True):
            if abs(c1 - c2) > EPSILON:
                return False
        return True

    def __add__(self, other: Any) -> Polynomial:
        if isinstance(other, int | float):
            coefficients = copy(self.coefficients)
            coefficients[0] += other
            return Polynomial(coefficients)

        coefficients = []
        for i in range(max(len(self.coefficients), len(other.coefficients))):
            c1 = 0 if i >= len(self.coefficients) else self.coefficients[i]
            c2 = 0 if i >= len(other.coefficients) else other.coefficients[i]
            coefficients.append(c1 + c2)

        return Polynomial(coefficients)

    def __radd__(self, other: Any) -> Polynomial:
        return self.__add__(other)

    def __neg__(self) -> Polynomial:
        return (-1) * self

    def __sub__(self, other: Any) -> Polynomial:
        return self + (-1) * other

    def __rsub__(self, other: Any) -> Polynomial:
        return other + (-1) * self

    def value(self, x: int | float) -> int | float:
        p = 0.0
        for i, c in enumerate(self.coefficients):
            p += c * x**i
        return p

    def degree(self) -> int:
        return self.d

    def __mul__(self, other: Any) -> Polynomial:
        if isinstance(other, int | float):
            coefficients = [c * other for c in self.coefficients]
            return Polynomial(coefficients)

        n1 = len(self.coefficients)
        n2 = len(other.coefficients)

        coefficients = []
        for _ in range(n1 * n2):
            coefficients.append(0)

        for i in range(n1):
            for j in range(n2):
                coefficients[i + j] += (
                    self.coefficients[i] * other.coefficients[j]
                )

        return Polynomial(coefficients)

    def __rmul__(self, other: Any) -> Polynomial:
        return self.__mul__(other)

    def __mod__(self, other: Any) -> Polynomial:
        if isinstance(other, int | float):
            coefficients = [c % other for c in self.coefficients]
            return Polynomial(coefficients)

        coefficients = [0] * (self.d - other.d + 1)

        mod = Polynomial(self.coefficients)
        while mod.d >= other.d:
            k = mod.d - other.d
            a = mod.coefficients[-1] // other.coefficients[-1]
            coefficients[-k] = a

            for i in range(other.d, -1, -1):
                mod.coefficients[i + k] -= a * other.coefficients[i]
            mod = Polynomial(mod)

        return mod

    def __iter__(self) -> Generator[float | int, None, None]:
        yield from self.coefficients

    def __next__(self) -> float | int:
        try:
            return next(self.__iter__())
        except AttributeError as exc:
            raise StopIteration from exc

    def mod(self, n: int) -> Polynomial:
        c = [i % n for i in self.coefficients]
        return Polynomial(c)
