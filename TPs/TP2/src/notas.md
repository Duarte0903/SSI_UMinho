## MTA (Mail Transmitor Agent)

- Vários processos a correr
- fazer a criação a remoção de utilizadores (dá para fazer com c algo parecido ao S8 com função system) - Fazer um ciclo while infinito no processo principal para correr comandos para isto
- Este programa provavelmente vai gerir o controlo de acesso (usar função system ??)

## Programa para enviar a mensagem

- Programa que conhece uma struct de mensagem 
- Abrir uma bash para um utilizidador (su username ??) 
- O utilizador invoca este programa que criar a mensagem e envia

## Cenas a considerar 

- Implementar queues de mensagens em ficheiros de texto e fazer controlo de acesso para gerir permissões
- Makefile cria (se não existir) o "utilizador" que vai correr o MTA 