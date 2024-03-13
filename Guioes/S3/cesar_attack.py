import sys

# Função para decifrar o texto cifrado usando a cifra de César.
# crypt (str): O texto cifrado.
# shift (int): O deslocamento (chave) usado para a cifra de César.
# result (str): O texto decifrado.

def decrypt(ciphertext, key):
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():
            shift = ord(char) - ord('A')
            decrypted_char = chr(((shift - key) % 26) + ord('A'))
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext

# Função para tentar encontrar a chave de cifra de César que decifra o texto e contém pelo menos uma das palavras fornecidas.
# crypt (str): O texto cifrado.
# words (list): Uma lista de palavras que podem estar presentes no texto decifrado.
# shift, dec (tuple): Uma tupla contendo a chave encontrada e o texto decifrado, ou (None, None) se nenhuma chave for encontrada.

def cesar_attack(ciphertext, words):
    for key in range(26):
        decrypted_text = decrypt(ciphertext, key)
        if any(word.upper() in decrypted_text for word in words):
            return key, decrypted_text
    return None, ''

# Função principal que executa o ataque à cifra de César.

def main():
    # Verifica se foram fornecidos argumentos suficientes
    if len(sys.argv) < 3:
        print("Usage: python3 cesar_attack.py <ciphertext> <word1> [<word2> ...]")
        sys.exit(1)

    ciphertext = sys.argv[1].upper()
    words = [word.upper() for word in sys.argv[2:]]

    key, decrypted_text = cesar_attack(ciphertext, words)

    if key is None:
        print("No matching key found.")
    else:
        print(chr(key + ord('A')))
        print(decrypted_text)

if __name__ == '__main__':
    main()