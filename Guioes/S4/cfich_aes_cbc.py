import os
import sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pad_data(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()

def encrypt_cbc(file_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    with open(file_path, 'rb') as file:
        plaintext = file.read()
        padded_plaintext = pad_data(plaintext)

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + ciphertext)

    print(f"Arquivo cifrado gravado em {encrypted_file_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python cfich_aes_cbc.py <fich> <chave>")
        sys.exit(1)

    file_path = sys.argv[1]
    key = sys.argv[2]

    if len(key) != 32:
        print("A chave deve ter 32 bytes (256 bits) para AES.")
        sys.exit(1)

    encrypt_cbc(file_path, key.encode('utf-8'))
