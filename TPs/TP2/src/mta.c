#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <grp.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include "../include/message.h"
#include "../include/mta_groups.h"
#include "../include/user_handle.h"

#define MAX_COMMAND_LENGTH 100
#define MAX_MESSAGE_LENGTH sizeof(Message)

int setup() {
    // verificar se o fifo mta_fifo existe
    if (mkfifo("mta_fifo", 0660) == -1) {
        if (errno != EEXIST) {
            perror("Error creating fifo\n");
            return -1;
        }
    }

    // verificar se o fifo mta_groups existe
    if (mkfifo("mta_groups", S_IRWXU | S_IRGRP | S_IWGRP) == -1) {
        if (errno != EEXIST) {
            perror("Error creating groups fifo\n");
            return -1;
        }
    }
    
    // verificar se o grupo mta_users existe
    if (system("getent group mta_users > /dev/null") != 0) {
        // Create the mta_users group
        if (system("sudo groupadd mta_users") != 0) {
            printf("Error creating group\n");
            return -1;
        }
    }

    // mudar as permissoes do fifo mta_fifo para o grupo mta_users com acl
    if (system("sudo setfacl -m g:mta_users:rwx mta_fifo") != 0) {
        printf("Error setting fifo group permissions\n");
        return -1;
    }

    // mudar as permissoes do fifo mta_groups para o grupo mta_users com acl
    if (system("sudo setfacl -m g:mta_users:rwx mta_groups") != 0) {
        printf("Error setting groups fifo group permissions\n");
        return -1;
    }

    // crair fifo para receber pedidos dos utilizadores
    if (mkfifo("client_fifo", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) == -1) {
        if (errno != EEXIST) {
            perror("Error creating fifo\n");
            exit(1);
        }
    }

    // remover settings the acl
    if (system("sudo setfacl -b client_fifo") != 0) {
        printf("Error removing fifo acl\n");
        return -1;
    }

    // permissoes acl
    if (system("sudo setfacl -m u::rw-,g::rw-,o::rw- client_fifo") != 0) {
        printf("Error setting fifo acl\n");
        return -1;
    }

    return 0;
}

void start_service() {
    int fifo_fd = open("mta_fifo", O_RDONLY);
    if (fifo_fd == -1) {
        perror("Error opening fifo\n");
        exit(-1);
    }

    while (1) {
        char buffer[MAX_MESSAGE_LENGTH];

        ssize_t bytes_read = read(fifo_fd, buffer, sizeof(buffer));

        if (bytes_read == -1) {
            perror("Error reading from fifo\n");
            close(fifo_fd);
            exit(-1);
        } else if (bytes_read == 0) {
            break;
        }

        Message received_msg;

        if (deserialize_message(buffer, &received_msg, sizeof(buffer)) != 0) {
            printf("Error deserializing message\n");
            close(fifo_fd);
            exit(-1);
        }

        printf("Message received from %s\n", received_msg.sender);

        // Mensagem para um unico utilizador
        if (strlen(received_msg.receiver) > 0) {
            pid_t pid = fork();

            if (pid == -1) {
                perror("Error forking\n");
                _exit(-1);
            }

            if (pid == 0) {
                char user_file[100];
                snprintf(user_file, sizeof(user_file), "./%s_file.csv", received_msg.receiver);
                FILE *file = fopen(user_file, "a");
                if (file == NULL) {
                    printf("Error opening user file\n");
                    _exit(-1);
                }

                // verficar se o sender e receiver pertencem ao grupo mta_users
                char command[100];
                snprintf(command, sizeof(command), "getent group mta_users | grep -q '\\b%s\\b'", received_msg.sender);
                if (system(command) != 0) {
                    printf("Error: sender does not belong to mta_users group\n");
                    _exit(-1);
                }
                snprintf(command, sizeof(command), "getent group mta_users | grep -q '\\b%s\\b'", received_msg.receiver);
                if (system(command) != 0) {
                    printf("Error: receiver does not belong to mta_users group\n");
                    _exit(-1);
                }

                // id da mensagem
                srand(time(NULL));
                int count = rand() % 1000;

                time_t now = time(NULL);
                struct tm *tm = localtime(&now);
                char timestamp[20];
                strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

                fprintf(file, "%d;%s;%s;%s;%s;%s\n", count+1, received_msg.sender, received_msg.receiver, received_msg.subject, received_msg.content, timestamp);
                fclose(file);

                // enviar mensagem para o fifo do utilizador (comunicacao sincrona)
                char fifo_name[100];
                snprintf(fifo_name, sizeof(fifo_name), "%s_fifo", received_msg.receiver);

                int client_fifo = open(fifo_name, O_WRONLY);

                if (client_fifo == -1) {
                    perror("Error opening fifo\n");
                    _exit(-1);
                }

                char serialize_message_buffer[MAX_MESSAGE_LENGTH];
                if (serialize_message(serialize_message_buffer, &received_msg, sizeof(serialize_message_buffer)) != 0) {
                    printf("Error serializing message\n");
                    _exit(-1);
                }

                if (write(client_fifo, serialize_message_buffer, sizeof(serialize_message_buffer)) == -1) {
                    perror("Error writing to fifo\n");
                    _exit(-1);
                }
                close(client_fifo);
                exit(0);
            }

            else {
                int status;
                if (waitpid(pid, &status, 0) == -1) {
                    perror("Error waiting for user child process\n");
                    _exit(-1);
                } else {
                    printf("Message saved to %s's file\n", received_msg.receiver);
                }
            }
        }

        // Mensagem para um grupo
        else if (strlen(received_msg.group) > 0 && strlen(received_msg.receiver) == 0) {
            pid_t pid = fork();

            if (pid == -1) {
                perror("Error forking\n");
                _exit(-1);
            }

            if (pid == 0) {
                struct group *grp;
                char **users;

                grp = getgrnam(received_msg.group);

                if (grp == NULL) {
                    printf("Error getting group\n");
                    exit(-1);
                }

                printf("Message received for group %s\n", received_msg.group);

                // verificar se o sender pertence ao grupo da mensagem
                char command[100];
                snprintf(command, sizeof(command), "getent group %s | grep -w %s | grep -q '\\b%s\\b'", received_msg.group, received_msg.group, received_msg.sender);
                if (system(command) != 0) {
                    printf("Error: sender does not belong to group\n");
                    _exit(-1);
                }

                users = grp->gr_mem;

                // escrever a mensagem no ficheiro do grupo
                char group_file[100];
                snprintf(group_file, sizeof(group_file), "./%s_group_file.csv", received_msg.group);
                FILE *file = fopen(group_file, "a");
                if (file == NULL) {
                    printf("Error opening group file\n");
                    _exit(-1);
                }

                // id da mensagem
                srand(time(NULL));
                int count = rand() % 1000;

                // timestamp
                time_t now = time(NULL);
                struct tm *tm = localtime(&now);
                char timestamp[20];
                strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

                fprintf(file, "%d;%s;%s;%s;%s;%s\n", count+1, received_msg.sender, received_msg.group, received_msg.subject, received_msg.content, timestamp);
                fclose(file);

                if (*users == NULL) {
                    printf("Error: group has no members\n");
                    exit(-1);
                }

                while (*users != NULL) {
                    pid_t pid2 = fork();

                    if (pid2 == -1) {
                        perror("Error forking\n");
                        _exit(-1);
                    }

                    if (pid2 == 0) {
                        // enviar mensagem para o fifo do utilizador (comunicacao sincrona)
                        char fifo_name[100];
                        snprintf(fifo_name, sizeof(fifo_name), "%s_fifo", *users);

                        int client_fifo = open(fifo_name, O_WRONLY);

                        if (client_fifo == -1) {
                            perror("Error opening fifo\n");
                            close(client_fifo);
                            _exit(-1);
                        }

                        char serialize_message_buffer[MAX_MESSAGE_LENGTH];
                        if (serialize_message(serialize_message_buffer, &received_msg, sizeof(serialize_message_buffer)) != 0) {
                            printf("Error serializing message\n");
                            close(client_fifo);
                            _exit(-1);
                        }

                        if (write(client_fifo, serialize_message_buffer, sizeof(serialize_message_buffer)) == -1) {
                            perror("Error writing to fifo\n");
                            close(client_fifo);
                            _exit(-1);
                        }  
                        close(client_fifo);
                        _exit(0);
                    }

                    else {
                        int status2; 
                        if (waitpid(pid2, &status2, 0) == -1) {
                            perror("Error waiting for user child process\n");
                            _exit(-1);
                        } else {
                            printf("Message saved to %s's file\n", *users);
                        }
                    }

                    users++;
                }
            }

            int status;
            if (waitpid(pid, &status, 0)) {
                printf("Message saved to group '%s' members\n", received_msg.group);
            }
        }
    }

    close(fifo_fd);
}

int main() {
    printf("Welcome to MTA\n");

    if (setup() != 0) {
        printf("Error setting up MTA\n");
        return -1;
    }

    pid_t group_request_pid = fork();
    if (group_request_pid == -1) {
        printf("Error forking to start group request listener\n");
        return -1;
    }
    if (group_request_pid == 0) {
        group_request_listener();
    }

    pid_t user_handle_pid = fork();
    if (user_handle_pid == -1) {
        printf("Error forking to start user handle\n");
        return -1;
    }
    if (user_handle_pid == 0) {
        user_handler();
    }
    
    pid_t service_pid = fork();
    if (service_pid == -1) {
        printf("Error forking to start service\n");
        return -1;
    }
    if (service_pid > 0) {
        while (1) {
            char command[MAX_COMMAND_LENGTH];

            printf("mta> ");
            scanf("%s", command);

            if (strcmp(command, "exit") == 0) {
                printf("Exiting MTA ...\n");
                break;
            }

            else if (strcmp(command, "help") == 0) {
                printf("-------------------------------------------\n");
                printf("Commands:\n");
                printf("-------------------------------------------\n");
                printf("exit - exits MTA\n");
                printf("help - shows this command\n");
                printf("-------------------------------------------\n");
            }

            else {
                printf("Invalid command\n");
            }
    }
    }

    else {
        start_service();
    }

    return 0;
}