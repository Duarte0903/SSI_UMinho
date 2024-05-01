# Serviço Local de Troca de Mensagens (TP2)

## MTA

O MTA é o programa que faz toda a gestão de utilizadores e grupos de utilizadores. É ainda responsável por colocar as mensagens nas inboxes dos utilizadores. Visto que este trabalha com permissões, deverá ser iniciado com permissões de administrador.

Comandos relevantes:

```bash
# Iniciar o MTA com permissões de administrador
$ sudo ./mta

# Adicionar um utilizador na linha de comandos do MTA
$ add_user

# Remover um utilizador na linha de comandos do MTA
$ delete_user

# Adicionar um grupo na linha de comandos do MTA
$ create_group

# Remover um grupo na linha de comandos do MTA
$ delete_group

# Adicionar utilizador a um grupo na linha de comandos do MTA
$ add_to_group

# Remover um utilizador de um grupo na linha de comandos do MTA
$ remove_from_group
```

## Client

O programa client permite a um utilizador do sistema interagir com o MTA, através do envio de mensagens. Estas mensagens podem ser dirigidas a um utilizador específico ou a um grupo de utilizadores.

Comandos relevantes:

```bash
# Enviar uma mensagem para um utilizador específico na linha de comandos do cliente
$ send

# Enviar uma mensagem para um grupo de utilizadores na linha de comandos do cliente
$ send_grp

# Mostrar a inbox do utilizador na linha de comandos do cliente
$ inbox
```

## Notas

- O serviço deve ser instalado com o comando `make`
- Tanto o MTA como o Client têm um comando `help` que contém informação sobre funcionalidades, e um comando `exit` para terminar o programa
- Nenhum comando possui argumentos
- Deve ser usado o comando `su <username>` para iniciar sessão com um utilizador do sistema antes the iniciar o Client
