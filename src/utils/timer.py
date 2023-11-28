from time import time
from typing import Any


def timer(function: Any) -> Any:
    def wrapper(*args: Any) -> Any:
        start_time = time()
        value = function(*args)
        end_time = time()
        print()
        print(
            f"Время выполнения функции {function.__name__} - {end_time-start_time} сек."
        )
        return value

    return wrapper
