# Guião S7

## Respostas das Questões

## Q1

Para verificar se as chaves fornecidas nos arquivos MSG_SERVER.key e MSG_SERVER.crt formam de facto um par de chaves RSA válido, seguimos os seguintes passos:

1. Utilizámos o comando **openssl x509 -text -noout -in MSG_SERVER.crt** para visualizar o conteúdo do certificado e confirmar se ele indica que a chave pública é do tipo RSA.

2. Utilizámos o comando **openssl rsa -text -noout -in MSG_SERVER.key** para visualizar o conteúdo da chave privada e confirmar se ela corresponde ao algoritmo RSA.

3. De seguida, comparou-se também o **módulo (número do produto de dois primos grandes) da chave privada** com o **módulo da chave pública** no certificado para garantir que correspondem. Para extrair esses módulos, utilizámos os seguintes comandos:
    - **openssl x509 -in MSG_SERVER.crt -noout -modulus;**
    - **openssl rsa -in MSG_SERVER.key -noout -modulus.**

4. Se todas essas **verificações** indicarem que a **chave pública no certificado é RSA** e a **chave privada também é RSA**, e se o **módulo** de ambas as chaves corresponderem, então é **razoável concluir que o par de chaves fornecidas é válido.**

## Q2

Durante a verificação, os campos a serem observados incluem o período de validade do certificado, a identidade do titular (sujeito), e quaisquer extensões relevantes, como propósito estendido de uso, políticas de certificado, etc.

## Relatório do Guião da Semana 7

