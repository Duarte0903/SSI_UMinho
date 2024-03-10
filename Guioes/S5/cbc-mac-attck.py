import sys, os, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def cbcmac_auth(m_bytes, k):
    # CBC mode requires padding
    padder = padding.PKCS7(128).padder()
    padded_m = padder.update(m_bytes) + padder.finalize()
    iv = bytearray(16)  # zero-filled IV
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_m) + encryptor.finalize()
    tag = ct[-16:]  # last block of ciphertext
    return tag

def cbcmac_verify(tag, m_bytes, k):
    padder = padding.PKCS7(128).padder()
    padded_m = padder.update(m_bytes) + padder.finalize()
    iv = bytearray(16)
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_m) + encryptor.finalize()
    newtag = ct[-16:]
    return tag == newtag

def cbcmac_lengthextension_example(m1, m2):
    key = os.urandom(32)
    tag1 = cbcmac_auth(m1, key)
    tag2 = cbcmac_auth(m2, key)

    r5 = cbcmac_verify(tag2, m2, key)
    return r5

def main(args=sys.argv):
    if len(args) != 3:
        print("Utilização: python3 cbc-mac.py <msg1> <msg2>")
    else:
        print(cbcmac_lengthextension_example(args[1].encode('utf-8'), args[2].encode('utf-8')))

if __name__ == '__main__':
    main()
