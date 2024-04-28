#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <grp.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>

#include "../include/message.h"

#define MAX_COMMAND_LENGTH 100
#define MAX_MESSAGE_LENGTH sizeof(Message)

int setup() {
    // verificar se o grupo mta_users existe
    if (system("getent group mta_users > /dev/null") != 0) {
        // criar grupo mta_users
        if (system("sudo groupadd mta_users") != 0) {
            printf("Error creating group\n");
            return -1;
        }

        // alterar as permissões do grupo mta_users
        if (system("sudo chmod g+wrx mta_users") != 0) {
            printf("Error changing group permissions\n");
            return -1;
        }
    }

    return 0;
}

int add_user() {
    char username[20];
    char password[20];

    printf("Enter username: ");
    scanf("%s", username);

    printf("Enter password: ");
    scanf("%s", password);

    // criar novo utilizador
    char user_add_command[100];
    snprintf(user_add_command, sizeof(user_add_command), "sudo useradd %s", username);
    if (system(user_add_command) != 0) {
        printf("Error creating user\n");
        return -1;
    }

    // adicionar password ao utilizador
    char password_command[100];
    snprintf(password_command, sizeof(password_command), "echo %s:%s | sudo chpasswd 2>/dev/null", username, password);
    if (system(password_command) == -1) {
        printf("Error setting password\n");
        return -1;
    }

    // criar a caixa de correio do utilizador
    char user_file[100];
    snprintf(user_file, sizeof(user_file), "./%s_file.csv", username);
    FILE *file = fopen(user_file, "w");
    if (file == NULL) {
        printf("Error creating user file\n");
        return -1;
    }
    fprintf(file, "sender;receiver;subject;content;time-stamp\n");
    fclose(file);

    // gerir as permissões do ficheiro
    if (chmod(user_file, 0644) != 0) {
        printf("Error setting file permissions\n");
        return -1;
    }

    // adicionar utilizador ao grupo mta_users
    char group_command[100];
    snprintf(group_command, sizeof(group_command), "sudo usermod -a -G mta_users %s", username);
    if (system(group_command) != 0) {
        printf("Error adding user to group\n");
        return -1;
    }

    // controlo de acesso ao ficheiro do utilizador com acl (access control list)
    char acl_command[200];
    snprintf(acl_command, sizeof(acl_command), "sudo setfacl -m g:%s:rw,o::-,m::rw  %s", username, user_file);
    if (system(acl_command) != 0) {
        printf("Error setting acl permissions for %s\n", username);
        return -1;
    }

    printf("User added successfully\n");

    return 0;
}

int delete_user() {
    char username[20];

    printf("Enter username: ");
    scanf("%s", username);

    // remover utilizador
    char user_delete_command[100];
    snprintf(user_delete_command, sizeof(user_delete_command), "sudo userdel -r -f %s 2>/dev/null", username);
    if (system(user_delete_command) != 0) {
        printf("Error deleting user\n");
        return -1;
    }

    // remover ficheiro do utilizador
    char user_file[100];
    snprintf(user_file, sizeof(user_file), "./%s_file.csv", username);
    if (remove(user_file) != 0) {
        printf("Error deleting user file\n");
        return -1;
    }

    printf("User deleted successfully\n");

    return 0;
}

int run() {
    pid_t pid = fork();
    int status;

    // criar fifo
    if (mkfifo("mta_fifo", 0660) == -1) {
        if (errno != EEXIST) {
            perror("Error creating fifo\n");
            return -1;
        }
    }

    if (chmod("mta_fifo", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
        perror("Error setting fifo permissions\n");
        return -1;
    }

    // alterar as permissões do fifo para o grupo mta_users com acl
    if (system("sudo setfacl -m g:mta_users:rwx mta_fifo") != 0) {
        printf("Error setting fifo group permissions\n");
        return -1;
    }

    int fifo_fd = open("mta_fifo", O_RDONLY);
    if (fifo_fd == -1) {
        perror("Error opening fifo\n");
        return -1;
    }

    if (pid == -1) {
        printf("Error forking\n");
        return -1;
    }

    // processo filho a espera de mensagens
    if (pid == 0) {
        char message_buffer[MAX_MESSAGE_LENGTH];

        while (1) {
            ssize_t bytes_read = read(fifo_fd, message_buffer, sizeof(message_buffer));

            if (bytes_read < 0) {
                perror("Error reading from fifo\n");
                return -1;
            } else if (bytes_read == 0) {
                break;
            }

            Message received_message; 

            printf("Received message\n");
            
            if (deserialize_message (message_buffer, &received_message, sizeof(message_buffer)) != 0) {
                printf("Error deserializing message\n");
                return -1;
            }

            char user_file[100];
            snprintf(user_file, sizeof(user_file), "./%s_file.csv", received_message.receiver);

            FILE *file = fopen(user_file, "a");
            if (file == NULL) {
                printf("Error opening user file\n");
                return -1;
            }

            // time-stamp
            time_t rawtime;
            struct tm *local_time;
            time(&rawtime);
            local_time = localtime(&rawtime);

            char timestamp[MAX_MESSAGE_LENGTH];
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);

            char message_string[MAX_MESSAGE_LENGTH + 1000]; 
            sprintf(message_string, "%s;%s;%s;%s;%s\n", received_message.sender, received_message.receiver, received_message.subject, received_message.content, timestamp);
            if (fprintf(file, "%s", message_string) < 0) {
                printf("Error writing to user file\n");
                return -1;
            }
            fclose(file);
        }

        printf("MTA mail service stopped running\n");
        exit(0);
    }

    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        printf("MTA mail service stopped running\n");
    }

    close(fifo_fd); 

    return 0;
}

int main() {
    printf("Welcome to MTA\n");

    if (setup() != 0) {
        printf("Error setting up MTA\n");
        return -1;
    }

    while(1) {
        char command[MAX_COMMAND_LENGTH];

        printf("mta> ");
        scanf("%s", command);

        if (strcmp(command, "add_user") == 0) {
            if (add_user() != 0) {
                printf("Error adding user\n");
            }
        }

        else if (strcmp(command, "delete_user") == 0) {
            if (delete_user() != 0) {
                printf("Error deleting user\n");
            }
        }

        else if (strcmp(command, "run") == 0) {
            printf("MTA mail service running ...\n");
            int run_return = run();
            if (run_return != 0) {
                printf("Error running MTA mail service\n");
            }
        }
        
        else if (strcmp(command, "exit") == 0) {
            break;
        }

        else if (strcmp(command, "help") == 0) {
            printf("Commands:\n");
            printf("add_user - adds user to the MTA\n");
            printf("delete_user - deletes user from the MTA\n");
            printf("run - runs MTA mail service\n");
            printf("exit - exits MTA\n");
            printf("help - shows this command\n");
        }
        
        else {
            printf("Unknown command\n");
        }
    }
    
    return 0;
}
