#include <stdio.h>
#include <syslog.h>

int main() {
    openlog("s10_ex1", LOG_PID|LOG_CONS, LOG_USER);

    setlogmask(LOG_UPTO(LOG_INFO));

    syslog(LOG_EMERG, "Mensagem de emergência: O sistema não é usável!");
    syslog(LOG_ALERT, "Mensagem de alerta: Situação crítica!");
    syslog(LOG_CRIT, "Mensagem crítica: Houve um erro crítico!");
    syslog(LOG_ERR, "Mensagem de erro: Ocorreu um erro!");
    syslog(LOG_WARNING, "Mensagem de aviso: Atenção, algo não está como esperado.");
    syslog(LOG_NOTICE, "Mensagem de notificação: Aviso normal.");
    syslog(LOG_INFO, "Mensagem informativa: Informação geral.");
    syslog(LOG_DEBUG, "Mensagem de depuração: Depuração de erros.");

    closelog();

    return 0;
}
