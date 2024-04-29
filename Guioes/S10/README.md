# Guião S10

## Relatório do Guião da Semana 10

### Exercicio proposto 1

A função openlog é chamada no início do programa para iniciar uma conexão com o sistema de log. Irá receber três argumentos: uma string que será anexada a cada mensagem de log, uma opção que indica que o PID do processo será anexado a cada mensagem e o identificador do tipo de programa.

A função setlogmask é usada para definir o nível de log. Neste caso, LOG_UPTO(LOG_INFO) significa que todas as mensagens de log até o nível de informação serão registadas.

Em seguida, várias chamadas para a função syslog são feitas. Cada chamada registra uma mensagem de log com um nível de prioridade específico. Os níveis de prioridade variam de LOG_EMERG, que indica uma condição de emergência que torna o sistema inutilizável, a LOG_DEBUG, que é usado para mensagens de depuração.

Finalmente, a função closelog é chamada para fechar a conexão com o sistema de log e o programa termina retornando 0, indicando que tudo correu bem.

Através do comando `journalctl -f` conseguimos comprovar que os logs foram efetivamente feitos:

```bash
    abr 29 21:23:29 vivobook s10_ex1[7202]: Mensagem de emergência: O sistema não é usável!
    abr 29 21:23:29 vivobook s10_ex1[7202]: Mensagem de alerta: Situação crítica!
    abr 29 21:23:29 vivobook s10_ex1[7202]: Mensagem crítica: Houve um erro crítico!
    abr 29 21:23:29 vivobook s10_ex1[7202]: Mensagem de erro: Ocorreu um erro!
    abr 29 21:23:29 vivobook s10_ex1[7202]: Mensagem de aviso: Atenção, algo não está como esperado.
    abr 29 21:23:29 vivobook s10_ex1[7202]: Mensagem de notificação: Aviso normal.
    abr 29 21:23:29 vivobook s10_ex1[7202]: Mensagem informativa: Informação geral.
```

### Exercicio Proposto 2

A função daemonize é responsável por transformar o processo atual em um daemon. Esta começa por criar um novo processo através da função fork. O processo pai então termina, enquanto o processo filho continua.

Na função main, a função daemonize é chamada para transformar o processo num daemon. Em seguida, a função openlog é chamada para iniciar o registro de log do sistema. O daemon entra em um loop infinito, registando uma mensagem de log a cada 5 segundos.

Para criar o serviço acedemos à diretoria `systemd/` e adicionamos o ficheiro `s10_ex2.service`: 

```txt
    [Unit]
    Description=Serviço s10 ex2
    After=network.target

    [Service]
    Type=simple
    ExecStart=/home/user/2324-G15/Guioes/S10/s10_ex2
    Restart=always

    [Install]
    WantedBy=multi-user.target  
```

De seguida utilizamos o comando `systemctl` para usar o serviço criado:

```bash
    sudo systemctl daemon-reload
    sudo systemctl start s10_ex2.service
    sudo systemctl stop s10_ex2.service
    sudo systemctl status s10_ex2.service
```