from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def encrypt_chacha20_poly1305(message, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    ct = cipher.encrypt(nonce, message.encode(), None)

    return urlsafe_b64encode(salt + nonce + ct)

def decrypt_chacha20_poly1305(ciphertext, password):
    data = urlsafe_b64decode(ciphertext)
    salt, nonce, ct = data[:16], data[16:28], data[28:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = ChaCha20Poly1305(key)
    decrypted_message = cipher.decrypt(nonce, ct, None)

    return decrypted_message.decode()

def main():
    password = input("password: ")
    message = input("texto: ")
    ciphertext = encrypt_chacha20_poly1305(message, password)
    decrypted_message = decrypt_chacha20_poly1305(ciphertext, password)

    print("Mensagem original:", message)
    print("Ciphertext:", ciphertext)
    print("Mensagem descriptografada:", decrypted_message)

if __name__ == "__main__":
    main()