# Respostas das Questões

## Q1

## Q2

O ataque bem-sucedido conhecido como bad_otp_attack não contradiz a alegação de "segurança absoluta" da cifra One-Time Pad (OTP). A segurança da cifra baseia-se na necessidade de uma chave verdadeiramente aleatória, secreta e do mesmo tamanho ou maior do que a mensagem a ser cifrada. No entanto, o sucesso do bad_otp_attack, que assume repetição na chave, indica uma implementação inadequada da cifra OTP. Embora o resultado condradiza a "segurança absoluta" em si, destaca a importância de cumprir os requisitos fundamentais para garantir a segurança. Caso a chave não seja verdadeiramente aleatória ou haja alguma repetição, a segurança da cifra OTP pode ser comprometida.

# Relatório do Guião da Semana 3

- **cesar.py:**
    1. Na função main é lido o input e percebe-se se é para cifrar ou decifrar.

    2. A operação de cifragem regebe uma chave e uma mensagem como argumentos. É calculado um valor numérico associado à chave. De seguida, a função preproc recebe a mensagem como argumento, itera sobre cada caractere da mesma. Se o caractere for alfabético, o adiciona a uma lista após converter para maiúsculas. No fim, a função preproc retorna a string resultante formada pelos caracteres alfabéticos em maiúsculas. De volta à função de decrifrar, é aplicada a cifragem inversa (com chave negativa) a cada caractere na mensagem. Por fim é retornada a mensagem decrifrada.

    3. A operação de cifragem oprera de forma semelhante à operação de decifragem. No entanto, é aplicada a cifragem com a chave original.

- **cesar_attack.py:**
    1. Após receber os argumentos é realizado um ataque de força bruta à cifra de cesar.

    2. A funçãoo cesar tenta todas as 26 possíveis chaves de deslocamento para decifrar a mensagem. Para tal usa a função dec_cesar que decifra uma mensagem cifrada aplicando um deslocamento inverso.

    3. Se encontrar uma correspondência com palavras conhecidas, retorna a chave e a mensagem decifrada. Caso contrário, retorna None.

- **vigenere.py:**

- **vigenere_attack.py:**

- **otp.py:**
    1. 