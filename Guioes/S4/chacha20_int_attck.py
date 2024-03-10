import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def modify_ciphertext(file_to_modify, position, new_plaintext):
    with open(file_to_modify, "rb") as f:
        ciphertext = f.read()

    # O nonce é de tamanho fixo em ChaCha20, então pegamos os primeiros 16 bytes do criptograma
    nonce = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Decifrando o bloco afetado para descobrir o estado do keystream
    cipher = Cipher(algorithms.ChaCha20(b"\x00" * 32, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    keystream_block = decryptor.update(ciphertext[position:position + 64]) + decryptor.finalize()

    # Obtendo o texto-limpo original na posição fornecida
    original_plaintext = bytearray(keystream_block)[:len(new_plaintext)]

    # Modificando o texto-limpo na posição especificada
    modified_keystream = bytearray(keystream_block)
    modified_keystream[:len(new_plaintext)] = bytearray(new_plaintext)

    # Realizando XOR entre o keystream modificado e o bloco do criptograma afetado
    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[position:position + 64] = bytes(x ^ y for x, y in zip(modified_keystream, ciphertext[position:position + 64]))

    # Gravando o criptograma modificado no arquivo
    with open(file_to_modify + ".attck", "wb") as f:
        f.write(nonce + bytes(modified_ciphertext))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")
        sys.exit(1)

    file_to_modify = sys.argv[1]
    position = int(sys.argv[2])
    original_plaintext = sys.argv[3].encode()
    new_plaintext = sys.argv[4].encode()

    modify_ciphertext(file_to_modify, position, new_plaintext)
    print("Ciphertext modified successfully.")

    # COMANDO: python chacha20_int_attck.py input.txt.enc 12 exemplo criptografado
