#include <stdio.h>
#include <unistd.h>  
#include <sys/types.h> 

#include "message.h"

int send_msg() {
    Message msg;
    
    printf("Destinatário: ");
    scanf("%s", msg.receiver);
    printf("Assunto: ");
    scanf("%s", msg.subject);
    printf("Mensagem: ");
    scanf("%s", msg.content);

    return 0;
}