from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def pbkdf2(password, salt, length, key_length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=length,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key[:key_length]

def encrypt_then_mac(password, plaintext):
    # Derive a new key for MAC
    mac_key = pbkdf2(password, b'mac_salt', 32, 32)

    # Encrypt using AES in CTR mode
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(mac_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Calculate HMAC over the encrypted text
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    mac = h.finalize()

    return (iv, ciphertext, mac)

def verify_then_decrypt(password, data):
    # Extract components
    iv, ciphertext, received_mac = data

    # Derive a new key for MAC
    mac_key = pbkdf2(password, b'mac_salt', 32, 32)

    # Verify MAC
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    computed_mac = h.finalize()

    if computed_mac != received_mac:
        raise ValueError("MAC verification failed")

    # Decrypt using AES in CTR mode
    cipher = Cipher(algorithms.AES(mac_key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_text

# Example usage:
password = b"your_password"
plaintext = b"Hello, this is a secret message!"

# Encrypt and MAC
cipher_data = encrypt_then_mac(password, plaintext)
print("Encrypted and MAC'd data:", cipher_data)

# Verify and decrypt
decrypted_text = verify_then_decrypt(password, cipher_data)
print("Decrypted text:", decrypted_text.decode('utf-8'))
