#include <stdio.h>
#include <unistd.h>  
#include <sys/types.h>
#include <string.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>

#include "../include/message.h"

#define MAX_MESSAGE_LENGTH sizeof(Message)
#define MAX_COMMAND_LENGTH 100
#define MAX_LINE_LENGTH 1024 
#define MAX_FIELDS 10        
#define DELIMITER ";" 

int setup(char *username) {
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (pw != NULL) {
        strcpy(username, pw->pw_name);
    } else {
        printf("Erro ao obter nome do usuário\n");
        return -1;
    }

    return 0;
}

int inbox(const char *username) {
    printf("-------------------------------------------\n");

    printf("Inbox:\n");

    printf("-------------------------------------------\n");

    char inbox_path[50];
    snprintf(inbox_path, sizeof(inbox_path), "%s_file.csv", username);

    FILE *file = fopen(inbox_path, "r");
    if (file == NULL) {
        printf("Erro ao abrir ficheiro\n");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    int first_line_skipped = 0;
    while (fgets(line, sizeof(line), file)) {
        if (!first_line_skipped) {
            first_line_skipped = 1;
            continue;
        }
        line[strcspn(line, "\n")] = '\0';
        
        char *field = strtok(line, DELIMITER);
        
        printf("Sender: %s\n", field);
        field = strtok(NULL, DELIMITER);
        printf("Receiver: %s\n", field);
        field = strtok(NULL, DELIMITER);
        printf("Subject: %s\n", field);
        field = strtok(NULL, DELIMITER);
        printf("Content: %s\n", field);
        
        printf("-------------------------------------------\n");
    }

    fclose(file);

    return 0;
}

int main() {
    char command[MAX_COMMAND_LENGTH];
    char username[20];

    if (setup(username) == -1) {
        printf("Erro ao configurar o cliente\n");
        return -1;
    }

    while (1) {
        printf("mta_client> ");
        scanf("%s", command);

        if (strcmp(command, "send") == 0) {
            send_msg(username);
        } 

        else if (strcmp(command, "inbox") == 0) {
            if (inbox(username) == -1) {
                printf("Erro ao mostrar inbox\n");
            }
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