import os
from pathlib import Path

DIRECTORY = Path(__file__).parent.parent / "data" / "lab4"


def change_encoding(file_path: Path) -> None:
    with open(file_path, encoding="IBM866") as file:
        data = file.read()

    with open(file_path, mode="w+", encoding="utf-8") as file:
        file.write(data)


files_paths = [DIRECTORY / path for path in os.listdir(DIRECTORY)]

for path in files_paths:
    change_encoding(path)
