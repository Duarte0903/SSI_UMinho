# Guião S7

## Respostas das Questões

## Q1

- Para verificar se as chaves fornecidas nos arquivos MSG_SERVER.key e MSG_SERVER.crt formam de facto um par de chaves RSA válido, seguimos os seguintes passos:
    1. Utilizámos o comando **openssl x509 -text -noout -in MSG_SERVER.crt** para visualizar o conteúdo do certificado e confirmar se ele indica que a chave pública é do tipo RSA.

    2. Utilizámos o comando **openssl rsa -text -noout -in MSG_SERVER.key** para visualizar o conteúdo da chave privada e confirmar se ela corresponde ao algoritmo RSA.

    3. De seguida, comparou-se também o **módulo (número do produto de dois primos grandes) da chave privada** com o **módulo da chave pública** no certificado para garantir que correspondem. Para extrair esses módulos, utilizámos os seguintes comandos:
        - **openssl x509 -in MSG_SERVER.crt -noout -modulus;**
        - **openssl rsa -in MSG_SERVER.key -noout -modulus.**

    4. Se todas essas **verificações** indicarem que a **chave pública no certificado é RSA** e a **chave privada também é RSA**, e se o **módulo** de ambas as chaves corresponderem, então é **razoável concluir que o par de chaves fornecidas é válido.**

## Q2

- Durante a verificação, os campos a serem observados incluem o período de validade do certificado, a identidade do titular (sujeito), e quaisquer extensões relevantes, como propósito estendido de uso, políticas de certificado, etc.

## Relatório do Guião da Semana 7
- O protocolo Station-to-Station (STS) é uma extensão do protocolo Diffie-Hellman que adiciona autenticação mútua entre os participantes. Aqui está uma explicação de como o protocolo é implementado nos códigos fornecidos:
**NOTA:** o programa inicia com o uso do comando **"pub_key"**

**Cliente (Client_sts.py):**
- **Inicialização:**
    1. O cliente carrega sua chave privada e certificado a partir dos arquivos MSG_CLI1.key e MSG_CLI1.crt, respectivamente.
    2. A chave privada é carregada para assinar mensagens, enquanto o certificado é usado para validar o certificado do servidor durante a troca de chaves.

- **Processamento da Mensagem:**
    1. Quando o cliente recebe uma mensagem do servidor, ele a processa para determinar o tipo de ação a ser tomada.
    2. Se a mensagem for do tipo "pub_key", o cliente envia a sua chave pública criada a partir da chave privada para o server.
    3. Se a mensagem for do tipo "server_pub_key", o cliente processa a chave pública e o certificado do servidor recebidos do servidor.
    4. Ele verifica a assinatura do servidor usando a chave pública do servidor e valida o certificado do servidor.
    5. Então, o cliente gera sua própria chave privada e pública Diffie-Hellman e calcula a chave compartilhada.
    6. Finalmente, o cliente assina uma mensagem com a sua chave pública Diffie-Hellman e o seu próprio certificado usando sua chave privada e envia de volta ao servidor.

**Servidor (Server_sts.py):**
- **Inicialização:**
    1. O servidor carrega a sua chave privada e certificado a partir dos arquivos MSG_SERVER.key e MSG_SERVER.crt, respectivamente.
    2. A chave privada é usada para assinar mensagens, enquanto o certificado é usado para validar o certificado do servidor durante a troca de chaves.

- **Processamento da Mensagem:**
    1. Quando o servidor recebe uma mensagem do cliente, ele a processa para determinar a ação a ser tomada.
    2. Se a mensagem for do tipo "client_pub_key", o servidor processa a chave pública recebida do cliente.
    3. Mais à frente, verifica a assinatura do cliente usando a chave pública do cliente e valida o certificado do cliente.
    4. Em seguida, o servidor gera a sua própria chave privada e pública Diffie-Hellman e calcula a chave compartilhada.
    5. Finalmente, o servidor assina uma mensagem com a sua chave pública Diffie-Hellman e o seu certificado usando sua chave privada e envia de volta para o cliente.
    
- Ambos os processos são semelhantes em termos de execução. Eles realizam a troca de chaves Diffie-Hellman e garantem a autenticidade dos participantes através da assinatura digital dos certificados. Ao final do protocolo, ambos os lados têm a chave compartilhada, permitindo a comunicação segura entre eles.