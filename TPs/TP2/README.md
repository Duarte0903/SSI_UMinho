# Serviço Local de Troca de Mensagens (TP2)

## MTA

O MTA é o programa que faz toda a gestão de utilizadores e grupos de utilizadores. É ainda responsável por colocar as mensagens nas inboxes dos utilizadores. Visto que este trabalha com permissões, deverá ser iniciado com permissões de administrador.

## Client

O programa client permite a um utilizador do sistema interagir com o MTA, através do envio de mensagens. Estas mensagens podem ser dirigidas a um utilizador específico ou a um grupo de utilizadores.

Comandos relevantes:

```bash
$ activate # activate user
$ deactivate # deactivate user
$ send # send message
$ send_grp # send message to group
$ inbox # show user inbox
$ get_msg # get a message by ID
$ groups # show user groups
$ group_members # show members of a group
$ create_group # create group
$ delete_group # delete group
$ add_users_to_group # add users to group
$ remove_users_from_group # remove users from group
$ exit # exit client
$ help # show this command

```

## Notas

- O serviço deve ser instalado com o comando `make`
- Tanto o MTA como o Client têm um comando `help` que contém informação sobre funcionalidades, e um comando `exit` para terminar o programa
- Nenhum comando possui argumentos
- Deve ser usado o comando `su <username>` para iniciar sessão com um utilizador do sistema antes de iniciar o Client
