import sys
import os
import getpass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_key_from_passphrase(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    return key


def encrypt(file_path, key):
    nonce = os.urandom(16)  # Gerar um nonce aleatório de 128 bits (16 bytes)

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(nonce + ciphertext)

    print(f"Arquivo cifrado gravado em {encrypted_file_path}")


def decrypt(file_path, key):
    with open(file_path, 'rb') as encrypted_file:
        nonce = encrypted_file.read(16)
        ciphertext = encrypted_file.read()

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file_path = file_path[:-4] + '.dec'
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(plaintext)

    print(f"Arquivo decifrado gravado em {decrypted_file_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python pbenc_chacha20.py <fich>")
        sys.exit(1)

    file_path = sys.argv[1]

    passphrase = getpass.getpass("Digite a passphrase: ")
    confirm_passphrase = getpass.getpass("Confirme a passphrase: ")

    if passphrase != confirm_passphrase:
        print("As passphrases não coincidem. Por favor, tente novamente.")
        sys.exit(1)

    salt = os.urandom(16)  # Gerar um salt aleatório para o PBKDF2
    key = generate_key_from_passphrase(passphrase, salt)

    encrypt(file_path, key)

    print("Criptograma gerado com sucesso.")
