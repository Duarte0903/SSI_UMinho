import sys

def preproc(text):
    return "".join(char.upper() for char in text if char.isalpha())

def encode(char, number):
    i = ord(char) - number
    while i > 90:
        i -= 26
    while i < 65:
        i += 26
    return chr(i)

def vigenere_decrypt(ciphertext, key):
    decrypted_text = ""
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            key_char = key[i % key_length]
            decrypted_char = encode(char, -ord(key_char) + 65)
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    return decrypted_text

def vigenere_attack(key_length, ciphertext, words):
    for key_start in range(key_length):
        possible_key = ""
        for i in range(key_start, len(ciphertext), key_length):
            possible_key += ciphertext[i]

        possible_key = possible_key.upper()

        print("Testing Key:", possible_key)

        decrypted_text = vigenere_decrypt(ciphertext, possible_key)
        print("Decrypted Text:", decrypted_text)

        for word in words:
            if word in decrypted_text:
                return possible_key, decrypted_text

    return "", ""

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 vigenere_attack.py <key_length> <ciphertext> <word1> <word2> ...")
        sys.exit(1)

    key_length = int(sys.argv[1])
    ciphertext = preproc(sys.argv[2])
    words = [preproc(word) for word in sys.argv[3:]]

    key, decrypted_text = vigenere_attack(key_length, ciphertext, words)

    if key:
        print(key)
        print(decrypted_text)
    else:
        print("")

if __name__ == "__main__":
    main()
