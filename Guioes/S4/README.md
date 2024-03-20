# Guião S4

## Respostas das Questões

### Q2

Um "NONCE" é uma valor de segurança usado em criptografia para garantir que uma chave secreta seja utilizada apenas uma vez. Ele é tipicamente utilizado em esquemas de criptografia simétrica. Quando um "NONCE" é fixo, isto é, não muda entre as mensagens criptografadas, isso pode ter sérias implicações na segurança da cifra.

Aqui estão alguns dos impactos de considerar um nonce fixo, como tudo 0:
- Reutilização de chaves: Se um "NONCE" fixo é utilizado, isso essencialmente faz com que a mesma chave seja utilizada para criptografar mensagens diferentes. A mesma chave nunca pode ser utilizada para criptografar duas mensagens diferentes.

- Vulnerabilidade a ataques de repetição: Quando um "NONCE" é fixo, um adversário pode capturar pares de mensagens criptografadas e, em seguida, retransmitir esses pares para o destinatário. Como a chave e o "NONCE" são os mesmos, o destinatário descriptografaria as mensagens corretamente, mesmo que já tenha recebido mensagens idênticas no passado. Isso pode levar a diversos tipos de ataques, como ataques de repetição ou de injeção.

- Vazamento de informação: Se o mesmo "NONCE" é usado repetidamente com a mesma chave, isso pode revelar informações sobre as mensagens criptografadas. Por exemplo, se uma mensagem é enviada com o nonce 0 e, em seguida, a mesma mensagem é enviada com o nonce 1, um observador pode inferir que apenas o nonce foi incrementado.

### Q3

O impacto de usar o programa chacha20_int_attck.py nos criptogramas produzidos pelos programas cfich_aes_cbc.py e cfich_aes_ctr.py seria inexistente. Isso acontece devido ao facto de que o chacha20_int_attck.py é projetado especificamente para manipular criptogramas gerados pelo algoritmo ChaCha20, enquanto os criptogramas produzidos por cfich_aes_cbc.py e cfich_aes_ctr.py são cifrados usando o algoritmo AES, que é diferente do ChaCha20. Portanto, o programa chacha20_int_attck.py não seria aplicável aos criptogramas gerados por AES CBC ou AES CTR.

## Relatório do Guião da Semana 4

Neste guião, implementamos diferentes programas em Python para cifrar arquivos, utilizando duas cifras simétricas populares: ChaCha20 e AES (Advanced Encryption Standard). Além disso, discutimos sobre a importância da integridade dos dados em sistemas de criptografia e exploramos o conceito de derivar chaves a partir de uma passphrase usando Key Derivation Functions (KDFs).

1. Programa cfich_chacha20.py
    - O programa cfich_chacha20.py foi desenvolvido para cifrar arquivos usando a cifra sequencial ChaCha20.
    - Ele aceita três operações: setup, enc e dec.
    - A operação setup é usada para criar um arquivo contendo uma chave apropriada para a cifra ChaCha20.
    - As operações enc e dec são usadas para cifrar e decifrar arquivos, respectivamente, usando a chave fornecida.
    - O programa agora suporta Password-Based Encryption, onde a chave é derivada a partir de uma passphrase fornecida pelo usuário, utilizando a KDF PBKDF2.

2. Programa chacha20_int_attck.py
    - O programa chacha20_int_attck.py foi projetado para ilustrar como a informação cifrada pode ser manipulada se um fragmento do texto limpo for conhecido.
    - Ele recebe como entrada o nome do arquivo contendo o criptograma, a posição onde o texto limpo é conhecido, o texto limpo original nessa posição e o - novo texto desejado nessa posição.
    - O programa então modifica o criptograma para refletir as alterações desejadas e grava o resultado no arquivo <fctxt>.attck.

3. Programas cfich_aes_cbc.py e cfich_aes_ctr.py
    - Os programas cfich_aes_cbc.py e cfich_aes_ctr.py foram criados para cifrar arquivos usando a cifra por blocos AES, nos modos CBC e CTR.
    - Eles recebem como entrada o nome do arquivo a cifrar e a chave de 256 bits (32 bytes) para o algoritmo AES.

4. Programa pbenc_chacha20.py~
    - O programa pbenc_chacha20.py foi pensado para armazenar segredos cryptográficas em ficheiros de maneira a estarem devidamente protegidas.
    - Deriva os segredos a partir de uma frasepass (uma palavrapasse mas é uma frase em vez de uma palavra) com recurso a uma Key Derivation Functions (KDF), o que se designa por Password-Based Encryption.
    - Armazena em ficheiros devidamente protegidos, esta por sua vez recorrendo a PasswordBased Encryption para a sua própria proteção.

Em resumo, este projeto nos proporcionou uma compreensão prática das operações de criptografia de arquivos, incluindo a cifra de blocos e a cifra sequencial, bem como a importância da integridade dos dados e o uso adequado de Password-Based Encryption para proteger chaves criptográficas.