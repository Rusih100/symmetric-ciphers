from src.ciphers import AES128

key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"

aes = AES128(cipher_key=key)

message = b"Hello AES-128! d"

cipher_message = aes.encrypt(message)

print(cipher_message)
decrypt_message = aes.decrypt(cipher_message)

print(message)
