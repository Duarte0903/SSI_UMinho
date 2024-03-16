# Guião S6

## Relatório do Guião da Semana 5

1. **Client_sec.py**
    - A **classe Client** inicializa o cliente com uma chave AES-GCM fixa de 256 bits.
    - A **função process** processa mensagens recebidas do servidor. Decifra a mensagem recebida e exibe na tela. Solicita uma nova mensagem ao user.
    - A **função tcp_echo_client** estabelece uma conexão assíncrona com o servidor. Entra num loop para processar as mensagens. Obtém uma mensagem do user através do **método process.** Cifra a mensagem com a chave AES-GCM e envia ao servidor. Lê a resposta do servidor e tenta decifrar usando a mesma chave. Se a autenticação da mensagem falhar, exibe uma mensagem de erro. O loop continua assim, até receber uma mensagem vazia do user ou do servidor.
    - A **função run_client** cria um novo evento de loop. Define o evento de loop recém-criado, como o evento de loop atual. Executa a **função tcp_echo_client** até que seja concluída.
    - O programa estabelece uma comunicação segura entre o cliente e o servidor, trocando mensagens cifradas e autenticadas usando o algoritmo AES-GCM. O cliente processa continuamente as mensagens recebidas do servidor e envia novas mensagens, até que a comunicação seja encerrada.

2. **Server_sec.py:**
    - A **função handle_echo** trata de uma conexão de cliente. Cria uma instância de ServerWorker para lidar com a conexão. Lê as mensagens do cliente, processa e envia de volta as respostas. Encerra a conexão quando uma mensagem vazia é recebida.
    - A **função run_server** inicializa um novo evento de loop e um servidor na porta especificada e o servidor fica em execução até que seja interrompido pelo usuário (pressionando Ctrl+C). Quando interrompido, fecha o servidor e o loop de eventos.
    - O servidor recebe conexões de clientes, processa as mensagens recebidas e envia de volta as respostas modificadas. Ele opera de forma assíncrona, permitindo que múltiplas conexões sejam tratadas simultaneamente.
 
3.  **Client_dh.py:**

4.  **Server_dh.pY:**
