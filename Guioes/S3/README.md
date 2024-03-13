# Respostas das Questões

## Q1

1. Método de Geração de Chave:
    - No programa otp.py, a chave é gerada aleatoriamente e é do mesmo tamanho que o texto a ser cifrado.
    - No programa bad_otp.py, a chave é gerada usando uma função que realiza operações bit a bit com base no texto original e na palavra fornecida. Esta é uma implementação fraca de OTP (One-Time Pad), que resulta em uma chave previsível se o texto original e a palavra forem conhecidos.

2. Segurança:
    - O programa otp.py implementa um OTP (One-Time Pad) verdadeiro, que é considerado criptograficamente seguro se usado corretamente com chaves aleatórias e usadas apenas uma vez.
    - O programa bad_otp.py implementa uma versão comprometida do OTP, onde a chave é previsível com base no texto original e na palavra fornecida. Isso enfraquece significativamente a segurança do sistema, tornando-o suscetível a ataques de força bruta e de análise de texto simples.

3. Tamanho da Chave:
    - O tamanho da chave no programa otp.py é igual ao tamanho do texto original.
    - No programa bad_otp.py, o tamanho da chave depende do tamanho da palavra fornecida. Se a palavra for mais curta que o texto original, ela será repetida para criar uma chave do mesmo comprimento que o texto original.

4. Desempenho:
    - O programa otp.py tende a ter melhor desempenho em termos de segurança, pois implementa um algoritmo de criptografia mais robusto.
    - O programa bad_otp.py é mais vulnerável a ataques e, portanto, menos seguro em comparação com o otp.py.

## Q2



# Relatório do Guião da Semana 3

- **cesar.py:**
    1. Na função main é lido o input e percebe-se se é para cifrar ou decifrar.

    2. A operação de cifragem regebe uma chave e uma mensagem como argumentos. É calculado um valor numérico associado à chave. De seguida, a função preproc recebe a mensagem como argumento, itera sobre cada caractere da mesma. Se o caractere for alfabético, o adiciona a uma lista após converter para maiúsculas. No fim, a função preproc retorna a string resultante formada pelos caracteres alfabéticos em maiúsculas. De volta à função de decrifrar, é aplicada a cifragem inversa (com chave negativa) a cada caractere na mensagem. Por fim é retornada a mensagem decrifrada.

    3. A operação de cifragem oprera de forma semelhante à operação de decifragem. No entanto, é aplicada a cifragem com a chave original.

- **cesar_attack.py:**
    1. Este código implementa um programa de ataque à cifra de César. Ele recebe um texto cifrado e uma lista de palavras como argumentos. 
    
    2. Em seguida, tenta decifrar o texto usando todas as chaves possíveis até encontrar uma chave que produza um texto decifrado contendo pelo menos uma das palavras fornecidas. 
    
    3. Se uma chave correspondente for encontrada, imprime a chave usada e o texto decifrado. Se nenhuma chave corresponder, ele imprime "No matching key found.".

- **vigenere.py:**
    1. Este programa implementa uma cifra de Vigenère simplificada para criptografar e descriptografar mensagens. Ele suporta duas operações principais cifragem (enc) e decifragem (dec).

    2. Aqui está uma explicação do programa:
        - **preproc(str):** é responsável por limpar a mensagem de entrada, removendo todos os caracteres que não são letras e convertendo as letras para maiúsculas.
        - **encode(str, number):** é responsável por realizar a operação de codificação (ou decodificação) de um único caracter. Ela desloca o caracter no alfabeto em um número específico de posições, garantindo que o resultado esteja sempre dentro do intervalo das letras maiúsculas ASCII (de 'A' a 'Z').
        - **enc(chave, mensagem) e dec(chave, mensagem):** são responsáveis por cifrar e decifrar uma mensagem, respectivamente. Elas iteram sobre cada caracter da mensagem de entrada, aplicando a codificação (ou decodificação) correspondente usando a chave. A chave é repetida conforme necessário para cifrar ou decifrar toda a mensagem.

- **vigenere_attack.py:**

- **otp.py:**
    1. Implementa as operações para um sistema de Cifra One-Time Pad (OTP). Ele possui três operações principais:
        - **setup:** Gera uma chave OTP aleatória com um número específico de bytes e salva-a num arquivo.
        - **enc:** Criptografa um arquivo de mensagem usando uma chave OTP e salva o texto cifrado num novo arquivo.
        - **dec:** Descriptografa um arquivo de texto cifrado usando a chave OTP correspondente e salva o texto decifrado num novo arquivo.

    2. Aqui está um resumo das principais funções:
        - **generate_random_bytes(num_bytes):** Gera uma sequência de bytes aleatórios usando a função os.urandom().
        - **read_bytes_from_file(filename):** Lê os bytes de um arquivo binário.
        - **otp_setup(num_bytes, key_filename):** Gera uma chave OTP de tamanho especificado e a salva num arquivo.
        - **otp_enc(message_filename, key_filename):** Criptografa uma mensagem usando uma chave OTP e salva o texto cifrado num arquivo.
        - **otp_dec(ciphertext_filename, key_filename):** Descriptografa um texto cifrado usando uma chave OTP e salva o texto decifrado num arquivo

- **bad_otp.py:**
    1. Este programa, chamado bad_otp.py, implementa uma aplicação de One-Time Pad (OTP) usando um gerador de números pseudo-aleatórios inseguro chamado bad_prng.

    2. Aqui está uma explicação do programa:
        - **bad_prng(n):** é uma implementação de um gerador de números pseudo-aleatórios inseguro. Ela utiliza a função random.randbytes(2) para gerar uma semente de 2 bytes e, em seguida, usa essa semente para inicializar o gerador de números pseudo-aleatórios da biblioteca random. A função então retorna n bytes gerados pelo gerador de números pseudo-aleatórios da biblioteca random.
        - **read_bytes_from_file(filename):** são responsáveis por ler os bytes de um arquivo binário.
        - **otp_setup(num_bytes, key_filename):** Gera uma chave OTP de tamanho especificado e a salva num arquivo.
        - **otp_enc(message_filename, key_filename):** Criptografa uma mensagem usando uma chave OTP e salva o texto cifrado num arquivo.
        - **otp_dec(ciphertext_filename, key_filename):** Descriptografa um texto cifrado usando uma chave OTP e salva o texto decifrado num arquivo

    3. O objetivo desta implementação é demonstrar os perigos de usar um gerador de números pseudo-aleatórios inseguro em uma aplicação criptográfica. A função bad_prng é insegura porque a semente é gerada com apenas 2 bytes de entropia, o que torna a sequência de números gerada previsível e vulnerável a ataques. Portanto, embora o programa funcione corretamente e possa criptografar e descriptografar mensagens, ele não oferece segurança real devido ao uso do bad_prng.