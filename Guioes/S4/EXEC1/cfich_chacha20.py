import sys
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_key_file(key_file):
    # Geração da chave usando PBKDF2
    password = os.urandom(16)  # Geração de uma senha aleatória
    salt = os.urandom(16)  # Geração de um salt aleatório
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)

    # Gravação da chave em um arquivo
    with open(key_file, "wb") as f:
        f.write(key)


def encrypt_file(file_to_encrypt, key_file):
    # Leitura da chave do arquivo
    with open(key_file, "rb") as f:
        key = f.read()

    # Geração de um nonce aleatório
    nonce = os.urandom(16)

    # Cifração do arquivo
    with open(file_to_encrypt, "rb") as f:
        plaintext = f.read()
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Gravação do criptograma e do nonce no arquivo de saída
    with open(file_to_encrypt + ".enc", "wb") as f:
        f.write(nonce)
        f.write(ciphertext)


def decrypt_file(file_to_decrypt, key_file):
    # Leitura da chave do arquivo
    with open(key_file, "rb") as f:
        key = f.read()

    # Leitura do nonce e do criptograma do arquivo de entrada
    with open(file_to_decrypt, "rb") as f:
        nonce = f.read(16)
        ciphertext = f.read()

    # Decifração do arquivo
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Gravação do texto-limpo no arquivo de saída
    with open(file_to_decrypt + ".dec", "wb") as f:
        f.write(plaintext)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("    python cfich_chacha20.py setup <fkey>")
        print("    python cfich_chacha20.py enc <fich> <fkey>")
        print("    python cfich_chacha20.py dec <fich> <fkey>")
        sys.exit(1)

    operation = sys.argv[1]
    if operation == "setup":
        if len(sys.argv) != 3:
            print("Usage: python cfich_chacha20.py setup <fkey>")
            sys.exit(1)
        key_file = sys.argv[2]
        generate_key_file(key_file)
        print("Key file generated successfully.")
    elif operation == "enc":
        if len(sys.argv) != 4:
            print("Usage: python cfich_chacha20.py enc <fich> <fkey>")
            sys.exit(1)
        file_to_encrypt = sys.argv[2]
        key_file = sys.argv[3]
        encrypt_file(file_to_encrypt, key_file)
        print("File encrypted successfully.")
    elif operation == "dec":
        if len(sys.argv) != 4:
            print("Usage: python cfich_chacha20.py dec <fich> <fkey>")
            sys.exit(1)
        file_to_decrypt = sys.argv[2]
        key_file = sys.argv[3]
        decrypt_file(file_to_decrypt, key_file)
        print("File decrypted successfully.")
    else:
        print("Invalid operation. Please use 'setup', 'enc', or 'dec'.")
        sys.exit(1)
