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

void message_listener(const char *username) {
    int fd;

    char fifo_name[50];
    snprintf(fifo_name, sizeof(fifo_name), "%s_fifo", username);
    fd = open(fifo_name, O_RDONLY);

    if (fd == -1) {
        printf("Erro ao abrir fifo\n");
        return;
    }

    while (1) {
        char buffer[MAX_MESSAGE_LENGTH];

        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));

        if (bytes_read == -1) {
            perror("Error reading from fifo\n");
            exit(EXIT_FAILURE);
        } else if (bytes_read == 0) {
            break;
        }// enviar mensagem para o fifo do utilizador (comunicacao sincrona)

        Message received_msg;

        if (deserialize_message(buffer, &received_msg, sizeof(buffer)) != 0) {
            printf("Error deserializing message\n");
            exit(EXIT_FAILURE);
        }

        pid_t pid = fork();

        if (pid < 0) {
            printf("Erro ao criar processo\n");
            return;
        }

        if (pid == 0) {
            printf("\n-------------------------------------------\n");
            printf("Nova mensagem recebida:\n");
            printf("De: %s\n", received_msg.sender);
            printf("Assunto: %s\n", received_msg.subject);
            printf("Conteúdo: %s\n", received_msg.content);
            printf("-------------------------------------------\n");
            printf("mta_client> ");
            exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
    }
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

    pid_t pid;

    if (setup(username) == -1) {
        printf("Erro ao configurar o cliente\n");
        return -1;
    }

    pid = fork();

    if (pid < 0) {
        printf("Erro ao criar processo\n");
        return -1;
    }

    if (pid > 0) {
        while (1) {
            printf("mta_client> ");
            scanf("%s", command);

            if (strcmp(command, "send") == 0) {
                send_msg(username);
            } 

            else if (strcmp(command, "send_grp") == 0) {
                send_grp_msg(username);
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
                printf("-------------------------------------------\n");
                printf("Comandos disponíveis:\n");
                printf("-------------------------------------------\n");
                printf("send - send message\n");
                printf("send_grp - send message to group\n");
                printf("inbox - show user inbox\n");
                printf("exit - exit client\n");
                printf("help - show this command\n");
                printf("-------------------------------------------\n");
            }
            
            else {
                printf("Comando inválido\n");
            }
        }
    }

    else {
        message_listener(username);
    }
    
    return 0;
}