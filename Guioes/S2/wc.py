import sys

def main(imp):
    print("Argumentos da linha de comando: ", imp)

    file = open(imp[1], "r")

    content = file.read()

    lines = content.split("\n")

    words = content.split()

    letters = [char for char in content if char.isalpha()]

    print("Número de linhas:", len(lines))

    print("Número de palavras:", len(words))

    print("Número de letras:", len(letters))

    file.close()

if __name__ == "__main__":
    main(sys.argv)