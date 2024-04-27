#include <stdio.h>
#include <unistd.h>  
#include <sys/types.h>
#include <string.h>

#include "../include/message.h"

#define MAX_COMMAND_LENGTH 100

int main() {
    char command[MAX_COMMAND_LENGTH];

    while (1) {
        printf("Comando: ");
        scanf("%s", command);

        if (strcmp(command, "send") == 0) {
            send_msg();
        } 

        else if (strcmp(command, "inbox") == 0) {
            
        }
        
        else if (strcmp(command, "exit") == 0) {
            printf("Obrigado e volte sempre ...\n");
            break;
        } 

        else if (strcmp(command, "help") == 0) {
            printf("Comandos disponíveis:\n");
            printf("send - send message\n");
            printf("inbox - show user inbox\n");
            printf("exit - exit client\n");
            printf("help - show this command\n");
        }
        
        else {
            printf("Comando inválido\n");
        }
    }
    
    return 0;
}