# symmetric-ciphers
Реализация симметричных шифров AES, DES, Магма, Кузнечик и Вермана.

## Реализованные симметричные шифры
- AES (128)
- DES
- Кузнечик / Grasshopper
- Магама / Magma
- Шифр Вермана / Verman 

> Блочные шифры AES, DES, Кузнечник и Магма поддерживают режимы шифрования ECB, CBC, CFB, OFB и CTR.

> Блочные шифры поддерживают дополнение блоков по стандарту PKCS7.

## Примеры шифрования на AES
### AES в режиме ECB
```python
from src.ciphers import AES
from src.ciphers.cipher_modes import ECB

aes = AES(
    cipher_key=b"0123456789abcdef",
    cipher_mode=ECB
)

message = aes.encrypt(b"Hello AES!")
print(message.hex())  # ebe90cfc91ebb262aa9856ff2678c2b7
```
   
### AES в решиме CBC
```python
from src.ciphers import AES
from src.ciphers.cipher_modes import CBC

aes = AES(
    cipher_key=b"0123456789abcdef",
    init_vector=b"0101010101010101",
    cipher_mode=CBC
)

message = aes.encrypt(b"Hello AES!")
print(message.hex())  # 4c0cfa14d39d9f354856ac1b8713fcc8
```

### AES в режиме CTR
```python
from src.ciphers import AES
from src.ciphers.cipher_modes import CTR

aes = AES(
    cipher_key=b"0123456789abcdef",
    nonce=b'\xa1\xf0yx\xf5\x04\xe6\xad',
    cipher_mode=CTR
)

message = aes.encrypt(b"Hello AES!")
print(message.hex())  # eab80e886f8fa46fe59130864bd98e71
```
