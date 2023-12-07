from pathlib import Path

BASE_DIR = Path(__file__).parent.parent / "data" / "lab2"


def change_encoding(file_path: Path) -> None:
    with open(file_path, encoding="IBM866") as file:
        data = file.read()

    with open(file_path, mode="w+", encoding="utf-8") as file:
        file.write(data)


files_paths = [
    BASE_DIR / "2.po",
    BASE_DIR / "2.z1",
    BASE_DIR / "2.z2",
    BASE_DIR / "2B.txt",
    BASE_DIR / "README.TXT",
]

for path in files_paths:
    change_encoding(path)
