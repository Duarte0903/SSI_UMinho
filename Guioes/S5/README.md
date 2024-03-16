# Guião S5

## Respostas das Questões

## Q1

Executar o programa chacha20_int_attck.py sobre um criptograma produzido por pbenc_chacha20_poly1305.pyuma pode ter sérias consequências:

1. **Confidencialidade:** a confidencialidade da mensagem original é comprometida, expondo informações sensíveis.

2. **Integridade:** manipulação não detectada da mensagem original, permitindo alterações não autorizadas.

## Q2

A mensagem m2 precisa ter mais de 16 bytes para que a mensagem m3 possa ser construída de forma a verificar com tag2. Isso ocorre porque a criação de m3 no código atual depende do comprimento de m2 para garantir que o último bloco cifrado seja modificado. Para contornar essa limitação, m3 precisaria ser construída de uma maneira que garantisse a inclusão de um bloco adicional no processo de cifragem, possivelmente duplicando m2 até que tenha um comprimento suficiente.

## Relatório do Guião da Semana 5

- **pbenc_aes_ctr_hmac.py:**
    A função pbkdf2 recebe uma senha, um salt, um comprimento total e um comprimento de chave como parâmetros. Ela usa o algoritmo PBKDF2HMAC para derivar uma chave a partir da senha fornecida. A chave derivada é então cortada para o comprimento da chave especificado e retornada.

    A função encrypt_then_mac recebe uma senha e um texto simples como parâmetros. Ela primeiro deriva uma chave usando a função pbkdf2 e, em seguida, usa essa chave para criptografar o texto simples usando o algoritmo AES em modo CTR. Em seguida, ela calcula um HMAC do texto cifrado usando a mesma chave e retorna o vetor de inicialização (IV), o texto cifrado e o HMAC.

    A função verify_then_decrypt recebe uma senha e um conjunto de dados criptografados como parâmetros. Ela primeiro deriva uma chave usando a função pbkdf2 e, em seguida, verifica o HMAC do texto cifrado. Se o HMAC verificado não corresponder ao HMAC recebido, ela lança um ValueError. Se o HMAC for verificado com sucesso, ela descriptografa o texto cifrado usando a chave derivada e retorna o texto descriptografado.

- **pbenc_chacha20_poly1305.py:**
    A função encrypt_chacha20_poly1305 recebe uma mensagem e uma senha como parâmetros. Ela primeiro gera um salt aleatório e usa o algoritmo PBKDF2HMAC para derivar uma chave a partir da senha fornecida. Em seguida, ela gera um nonce aleatório e usa a chave para criptografar a mensagem usando o algoritmo ChaCha20Poly1305. A função retorna a concatenação do salt, do nonce e do texto cifrado, tudo codificado em base64.

    A função decrypt_chacha20_poly1305 recebe um texto cifrado e uma senha como parâmetros. Ela primeiro decodifica o texto cifrado de base64 e extrai o salt, o nonce e o texto cifrado. Em seguida, ela usa o algoritmo PBKDF2HMAC para derivar a chave a partir da senha fornecida usando o salt. Ela usa a chave para descriptografar o texto cifrado usando o algoritmo ChaCha20Poly1305 e retorna a mensagem descriptografada.    

- **pbenc_aes_gcm.py:**
    A função encrypt_aes_gcm recebe uma mensagem e uma senha como parâmetros. Primeiro, ela gera um "salt" aleatório de 16 bytes usando a função os.urandom. O "salt" é usado para garantir que a mesma senha não resulte na mesma chave de criptografia, mesmo que a mesma mensagem seja criptografada mais de uma vez. Em seguida, ela usa o algoritmo PBKDF2HMAC para derivar uma chave de criptografia da senha fornecida. A chave é então usada para criar um objeto Cipher que usa o algoritmo AES no modo GCM. A mensagem é então criptografada e o resultado é codificado em base64 antes de ser retornado.

    A função decrypt_aes_gcm faz o processo inverso. Ela recebe um texto cifrado e uma senha, decodifica o texto cifrado de base64 para bytes, extrai o "salt", o "nonce", a tag e o texto cifrado, e usa o mesmo algoritmo PBKDF2HMAC para derivar a chave de criptografia da senha. A chave é então usada para criar um objeto Cipher que usa o algoritmo AES no modo GCM para descriptografar a mensagem.

- **cbc-mac-attack.py:**
    A função cbcmac_auth(m_bytes, k) recebe uma mensagem e uma chave como parâmetros. A mensagem é preenchida usando o esquema de preenchimento PKCS7 para garantir que ela tenha o comprimento correto para a criptografia AES. Em seguida, um objeto Cipher é criado usando o algoritmo AES, o modo CBC e um vetor de inicialização (IV) preenchido com zeros. A mensagem preenchida é então criptografada e o último bloco do texto cifrado é retornado como a tag MAC. 

    A função cbcmac_verify(tag, m_bytes, k) faz o mesmo processo de preenchimento e criptografia que cbcmac_auth(m_bytes, k). Em seguida, compara a tag MAC fornecida com a tag MAC do texto cifrado recém-criptografado. Se as tags corresponderem, a função retorna True, indicando que a mensagem é autêntica. 

    A função cbcmac_lengthextension_example(m1, m2) gera uma chave aleatória e usa cbcmac_auth(m_bytes, k) para gerar tags MAC para duas mensagens diferentes. Em seguida, verifica a autenticidade da segunda mensagem e sua tag MAC usando cbcmac_verify(tag, m_bytes, k). O resultado dessa verificação é retornado.