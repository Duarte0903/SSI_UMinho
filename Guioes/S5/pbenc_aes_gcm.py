from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def encrypt_aes_gcm(message, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    nonce = os.urandom(12)  # O nonce deve ter 12 bytes para o AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()

    return urlsafe_b64encode(salt + nonce + encryptor.tag + ct)

def decrypt_aes_gcm(ciphertext, password):
    data = urlsafe_b64decode(ciphertext)
    salt, nonce, tag, ct = data[:16], data[16:28], data[28:44], data[44:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ct) + decryptor.finalize()

    return decrypted_message.decode()

# Exemplo de uso
password = "senha123"
message = "Olá, mundo!"
ciphertext = encrypt_aes_gcm(message, password)
decrypted_message = decrypt_aes_gcm(ciphertext, password)

print("Mensagem original:", message)
print("Ciphertext:", ciphertext)
print("Mensagem descriptografada:", decrypted_message)