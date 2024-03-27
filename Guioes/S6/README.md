# Guião S6

## Relatório do Guião da Semana 6

1. **Client_sec.py**
    - A função **process** é responsável por **processar mensagens enviadas e recebidas pelo cliente**. Ele recebe uma mensagem como entrada (msg). Se a mensagem não estiver vazia, ela é **descriptografada usando a chave e o nonce fornecidos**. A mensagem descriptografada é então exibida na tela. O método então solicita ao usuário **uma nova mensagem para enviar ao servidor**. Se o comprimento da nova mensagem for **zero**, significa que o **usuário deseja encerrar a conexão**, e o método retorna None. Caso contrário, a nova mensagem é **criptografada e retornada para ser enviada ao servidor**.

    - A função **tcp_echo_client()**: é assíncrona e define a lógica do cliente. Ela cria uma **conexão TCP com o servidor em       '127.0.0.1' na porta conn_port**. Uma instância da **classe Client é criada para lidar com a comunicação com o servidor**. A função então entra em um **loop onde recebe mensagens do usuário** e as **envia para o servidor** e recebe e processa as respostas do servidor. Quando uma **mensagem vazia é recebida do servidor**, a conexão é encerrada.
    
    - A função **run_client** é responsável por **executar o cliente**. Ela obtém o loop de eventos assíncronos padrão **(asyncio.get_event_loop()) e executa a função tcp_echo_client() até a conclusão**.


2. **Server_sec.py:**

    - A função **process** é responsável por processar as **mensagens recebidas do cliente**. Ele primeiro **decifra a mensagem usando a chave e o nonce fornecidos**. Em seguida, converte o **texto decifrado para maiúsculas e o codifica novamente**. Finalmente, **criptografa a mensagem modificada** usando a mesma chave e um novo nonce e a **retorna para ser enviada de volta ao cliente**.

    - A função **handle_echo** manipula uma **conexão de cliente**. Quando um **cliente se conecta**, ela cria uma instância de ServerWorker para lidar com essa **conexão específica**. Em seguida, entra num **loop onde lê mensagens do cliente**, passa-as para o método **process da instância ServerWorker** e envia as **respostas de volta ao cliente**. O loop continua até que não haja mais dados para ler do cliente. Se o cliente fechar a conexão, o loop termina e a conexão é fechada.

    - A função **run_server** é responsável por **iniciar o servidor**. Ela cria um novo **loop de eventos**, inicia o servidor na interface '127.0.0.1' e na porta especificada (conn_port) usando a **função asyncio.start_server**. Em seguida, entra em um loop infinito (loop.run_forever()) para continuar a **aceitar novas conexões** até que seja interrompido por um **sinal de interrupção (Ctrl + C)**. Quando isso acontece, o servidor é fechado e o loop de eventos é encerrado.
 
3.  **Client_dh.py:**
    - A classe Client é a implementação do cliente. No método __init__, o cliente é iniciado com um socket opcional, um contador de mensagens e uma chave partilhada. O método process é usado para processar mensagens recebidas do servidor. Na primeira mensagem, o cliente gera parâmetros Diffie-Hellman, cria uma chave privada e troca essa chave com a chave pública do servidor para criar uma chave partilhada. Essa chave partilhada é então usada para derivar uma chave de 32 bytes usando o HKDF (Key Derivation Function baseado em HMAC). A chave pública do cliente é então retornada em formato PEM. Para todas as outras mensagens, o cliente simplesmente imprime a mensagem recebida e solicita uma nova mensagem para enviar.

    - A função tcp_echo_client é uma função assíncrona que lida com a lógica de conexão e comunicação do cliente. Esta abre uma conexão para o servidor, cria uma instância do cliente e entra em loop de leitura e escrita de mensagens. O loop continua até que não haja mais mensagens para ler.

    - Finalmente, a função run_client obtém o loop de eventos atual do asyncio e executa a função tcp_echo_client até que ela seja concluída. A chamada para run_client no final do script inicia o cliente.

4.  **Server_dh.py:**
    - A classe ServerWorker é a implementação do servidor. No método __init__, o servidor é iniciado com um ID, um endereço opcional, um contador de mensagens e parâmetros Diffie-Hellman. O servidor gera uma chave privada a partir dos parâmetros Diffie-Hellman e obtém a chave pública correspondente. A chave pública é então serializada em formato PEM para ser enviada ao cliente. O método process é usado para processar mensagens recebidas do cliente. Este descodifica a mensagem, imprime a mensagem recebida, converte a mensagem para maiúsculas, codifica a mensagem novamente e retorna a nova mensagem. Se a nova mensagem estiver vazia, o método retorna None, o que indica que a conexão deve ser encerrada.

    - A função handle_echo é uma função assíncrona que lida com a lógica de conexão e comunicação do servidor. Ela aceita uma nova conexão, cria uma instância do servidor e entra em um loop de leitura e escrita de mensagens. O loop continua até que não haja mais mensagens para ler.

    - Finalmente, a função run_server obtém o loop de eventos atual do asyncio e executa a função handle_echo até que ela seja concluída. A chamada para run_server no final do script inicia o servidor.
