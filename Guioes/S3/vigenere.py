import sys

def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def encode(str, number):
    i = ord(str)
    i += number
    
    while i > 90:
       i -= 91
       i += 65
    
    while i < 65:
        i = 64 - i
        i = 90 - i
        
    return chr(i)

def enc(chave, mensagem):
    str_code = preproc(mensagem)
    result_string = ""
    i = -1
    
    code = []
    for char in chave:
        number = ord(char) - 65
        code.append(number)

    for char in str_code:
        if i == len(code) - 1:
            i = 0
            result_string = result_string + encode(char, code[i])

        else:
            i += 1
            result_string = result_string + encode(char, code[i])

    return result_string

def dec(chave, mensagem):
    str_code = preproc(mensagem)
    result_string = ""
    i = -1

    code = []
    for char in chave:
        number = ord(char) - 65
        code.append(number)

    for char in str_code:
        if i == len(code) - 1:
            i = 0
            result_string = result_string + encode(char, -code[i])

        else:
            i += 1
            result_string = result_string + encode(char, -code[i])

    return result_string

def main(imp):
    if len(imp) != 4:
        print("Argumentos insuficientes")
        return

    operacao = imp[1]
    chave = imp[2]
    mensagem = imp[3]

    if operacao == "enc":
        print(enc(chave, mensagem))

    elif operacao == "dec":
        print(dec(chave, mensagem))

if __name__ == '__main__':
    main(sys.argv)