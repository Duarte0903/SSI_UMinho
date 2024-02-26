import sys

def preproc(str):
      l = []
      for c in str:
          if c.isalpha():
              l.append(c.upper())
      return "".join(l) 

def cifra(str, number):
    i = ord(str)
    i += number
    
    while i > 90:
        i -= 91
        i += 65
    
    while i < 65:
        i = 64 - i
        i = 90 - i
    
    return chr(i)

def dec(chave, mensagem):
    chave = ord(chave) - 65
    str_compact = preproc(mensagem)
    result_string = result_string = ''.join(map(lambda x: cifra(x, -chave), str_compact))
    return result_string

def enc(chave, mensagem):
    chave = ord(chave) - 65
    str_compact = preproc(mensagem)
    result_string = result_string = ''.join(map(lambda x: cifra(x, chave), str_compact))
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