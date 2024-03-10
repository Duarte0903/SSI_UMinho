import sys

def bad_otp_attack(texto_a_cifrar, palavras, crip):
    for chave in range(26):
        decifrado = ""
        for char in texto_a_cifrar:
            if char.isalpha():
                decifrado += chr((ord(char) - 65 - chave) % 26 + 65)
            else:
                decifrado += char
        decifrado = decifrado.upper()
        print("Testing Key:", chave)
        print("Decrypted Text:", decifrado)
        for word in palavras:
            if word in decifrado:
                return chave, decifrado
    return "", ""

def main(imp):
    if len(imp) < 3:
        print("Argumentos insuficientes")
        sys.exit(1)

    texto_a_cifrar = imp[1]
    palavras = imp[2:]

    with open("ptxt.txt.enc", "r") as file:
        crip = file.read().splitlines()
        chave, decifrado = bad_otp_attack(texto_a_cifrar, palavras, crip)
        if chave:
            print(chave)
            print(decifrado)
        else:
            print("")


if __name__ == "__main__":
    main(sys.argv)