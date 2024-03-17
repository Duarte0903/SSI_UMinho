# Guião S6

## Relatório do Guião da Semana 6

1. **Client_sec.py**
    - A **classe Client** inicia o cliente com uma chave AES-GCM fixa de 256 bits.

    - A **função process** processa mensagens recebidas do servidor. Decifra a mensagem recebida e exibe na tela. Solicita uma nova mensagem ao user.

    - A **função tcp_echo_client** estabelece uma conexão assíncrona com o servidor. Entra num loop para processar as mensagens. Obtém uma mensagem do user através do **método process.** Cifra a mensagem com a chave AES-GCM e envia ao servidor. Lê a resposta do servidor e tenta decifrar usando a mesma chave. Se a autenticação da mensagem falhar, exibe uma mensagem de erro. O loop continua assim, até receber uma mensagem vazia do user ou do servidor.

    - A **função run_client** cria um novo evento de loop. Define o evento de loop recém-criado, como o evento de loop atual. Executa a **função tcp_echo_client** até que seja concluída.

    - O programa estabelece uma comunicação segura entre o cliente e o servidor, trocando mensagens cifradas e autenticadas usando o algoritmo AES-GCM. O cliente processa continuamente as mensagens recebidas do servidor e envia novas mensagens, até que a comunicação seja encerrada.

2. **Server_sec.py:**
    - A **função handle_echo** trata de uma conexão de cliente. Cria uma instância de ServerWorker para lidar com a conexão. Lê as mensagens do cliente, processa e envia de volta as respostas. Encerra a conexão quando uma mensagem vazia é recebida.

    - A **função run_server** inicializa um novo evento de loop e um servidor na porta especificada e o servidor fica em execução até que seja interrompido pelo usuário (pressionando Ctrl+C). Quando interrompido, fecha o servidor e o loop de eventos.

    - O servidor recebe conexões de clientes, processa as mensagens recebidas e envia de volta as respostas modificadas. Ele opera de forma assíncrona, permitindo que múltiplas conexões sejam tratadas simultaneamente.
 
3.  **Client_dh.py:**
    - A classe Client é a implementação do cliente. No método __init__, o cliente é iniciado com um socket opcional, um contador de mensagens e uma chave partilhada. O método process é usado para processar mensagens recebidas do servidor. Na primeira mensagem, o cliente gera parâmetros Diffie-Hellman, cria uma chave privada e troca essa chave com a chave pública do servidor para criar uma chave partilhada. Essa chave partilhada é então usada para derivar uma chave de 32 bytes usando o HKDF (Key Derivation Function baseado em HMAC). A chave pública do cliente é então retornada em formato PEM. Para todas as outras mensagens, o cliente simplesmente imprime a mensagem recebida e solicita uma nova mensagem para enviar.

    - A função tcp_echo_client é uma função assíncrona que lida com a lógica de conexão e comunicação do cliente. Esta abre uma conexão para o servidor, cria uma instância do cliente e entra em loop de leitura e escrita de mensagens. O loop continua até que não haja mais mensagens para ler.

    - Finalmente, a função run_client obtém o loop de eventos atual do asyncio e executa a função tcp_echo_client até que ela seja concluída. A chamada para run_client no final do script inicia o cliente.

4.  **Server_dh.py:**
    - A classe ServerWorker é a implementação do servidor. No método __init__, o servidor é iniciado com um ID, um endereço opcional, um contador de mensagens e parâmetros Diffie-Hellman. O servidor gera uma chave privada a partir dos parâmetros Diffie-Hellman e obtém a chave pública correspondente. A chave pública é então serializada em formato PEM para ser enviada ao cliente. O método process é usado para processar mensagens recebidas do cliente. Este descodifica a mensagem, imprime a mensagem recebida, converte a mensagem para maiúsculas, codifica a mensagem novamente e retorna a nova mensagem. Se a nova mensagem estiver vazia, o método retorna None, o que indica que a conexão deve ser encerrada.

    - A função handle_echo é uma função assíncrona que lida com a lógica de conexão e comunicação do servidor. Ela aceita uma nova conexão, cria uma instância do servidor e entra em um loop de leitura e escrita de mensagens. O loop continua até que não haja mais mensagens para ler.

    - Finalmente, a função run_server obtém o loop de eventos atual do asyncio e executa a função handle_echo até que ela seja concluída. A chamada para run_server no final do script inicia o servidor.
