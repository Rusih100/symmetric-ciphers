from pathlib import Path

BASE_DIR = Path(__file__).parent.parent / "data" / "lab3"


def change_encoding(file_path: Path) -> None:
    with open(file_path, encoding="IBM866") as file:
        data = file.read()

    with open(file_path, mode="w+", encoding="utf-8") as file:
        file.write(data)


files_paths = [
    BASE_DIR / "1.15",
    BASE_DIR / "2.15",
    BASE_DIR / "3.15",
    BASE_DIR / "4.15",
    BASE_DIR / "5.15",
    BASE_DIR / "6.15",
    BASE_DIR / "7.15",
    BASE_DIR / "8.15",
    BASE_DIR / "9.15",
    BASE_DIR / "10.15",
    BASE_DIR / "README.TXT",
]

for path in files_paths:
    change_encoding(path)