import sys

def dec_cesar(crypt, shift):
    result = ""
    for c in crypt:
        if c.isalpha():
            i = ord(c) - shift
            if i < 65:
                i = 90 - (64 - i)
            result += chr(i)
        else:
            result += c
    return result

def cesar(crypt, words):
    for word in words:
        for shift in range(26):
            dec = dec_cesar(crypt, shift)
            if word.lower() in dec.lower():
                return shift, dec
    return None, None

def main(imp):
    if len(imp) != 4:
        print("Argumentos insuficientes")
        return
    
    crypt = imp[1]
    word1 = imp[2]
    word2 = imp[3]

    shift, dec = cesar(crypt, [word1, word2])

    if shift is not None:
        print(chr(ord('A') + shift))
        print(dec)

    else:
        print("Não foi possível encontrar a chave")

if __name__ == '__main__':
    main(sys.argv)