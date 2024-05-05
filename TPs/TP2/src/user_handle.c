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

#include "../include/user_handle.h"

void user_handler() {
    // crair fifo para receber pedidos dos utilizadores
    if (mkfifo("client_fifo", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) == -1) {
        if (errno != EEXIST) {
            perror("Error creating fifo\n");
            exit(1);
        }
    }

    // remover settings the acl
    system("sudo setfacl -b client_fifo");

    // permissoes acl
    system("sudo setfacl -m u::rw-,g::rw-,o::rw- client_fifo");

    int fd;

    printf("Listening for user requests...\n");

    while (1) {
        fd = open("client_fifo", O_RDONLY);
        if (fd == -1) {
            perror("Error opening fifo for reading\n"); 
            break;
        }

        User_request user_request;

        ssize_t bytes_read = read(fd, &user_request, sizeof(User_request));

        if (bytes_read == -1) {
            perror("Error reading from fifo\n");
            break;
        } else if (bytes_read == 0) {
            printf("Fifo closed\n");
            break;
        }
        
        printf("Pedido recebido de %s\n", user_request.username);

        pid_t pid = fork();

        if (pid < 0) {
            printf("Erro ao criar processo\n");
            break;
        }

        if (pid == 0) {
            if (user_request.flag == 0) {
                if (activate_user(user_request.username) != 0) {
                    printf("Erro ao ativar utilizador\n");
                }
                printf("Utilizador %s ativado\n", user_request.username);
            } 
            
            else if (user_request.flag == 1) {
                if (deactivate_user(user_request.username) != 0) {
                    printf("Erro ao desativar utilizador\n");
                }
                printf("Utilizador %s desativado\n", user_request.username);
            } 
            
            else {
                printf("Flag inválida.\n");
            }
        }

        close(fd);
    }
}

int activate_user(const char *username) {
    // criar a caixa de correio do utilizador
    char user_file[100];
    snprintf(user_file, sizeof(user_file), "./%s_file.csv", username);
    FILE *file = fopen(user_file, "w");
    if (file == NULL) {
        printf("Error creating user file\n");
        return -1;
    }
    fprintf(file, "id;sender;receiver;subject;content;time-stamp\n");
    fclose(file);

    // criar o fifo do cliente
    char fifo_name[100];
    snprintf(fifo_name, sizeof(fifo_name), "%s_fifo", username);
    if (mkfifo(fifo_name, 0660) == -1) {
        if (errno != EEXIST) {
            perror("Error creating fifo\n");
            return -1;
        }
    }

    // adicionar utilizador ao grupo mta_users
    char group_command[100];
    snprintf(group_command, sizeof(group_command), "sudo usermod -a -G mta_users %s", username);
    if (system(group_command) != 0) {
        printf("Error adding user to group\n");
        return -1;
    }

    // controlo de acesso ao ficheiro do utilizador com acl (access control list)
    char remove_acl_command[200];
    snprintf(remove_acl_command, sizeof(remove_acl_command), "sudo setfacl -b %s", user_file);
    if (system(remove_acl_command) != 0) {
        printf("Error removing acl permissions\n");
        return -1;
    }

    char acl_command[200];
    snprintf(acl_command, sizeof(acl_command), "sudo setfacl -m u::rw-,g:%s:rw-,o::--- %s", username, user_file);
    if (system(acl_command) != 0) {
        printf("Error setting acl permissions for %s\n", username);
        return -1;
    }

    // dar permissões do fifo ao grupo (group_name = username) do client com acl
    char fifo_acl_command[200];
    snprintf(fifo_acl_command, sizeof(fifo_acl_command), "sudo setfacl -m g:%s:rwx %s", username, fifo_name);
    if (system(fifo_acl_command) != 0) {
        printf("Error setting acl permissions for %s group\n", username);
        return -1;
    }

    printf("User added successfully\n");

    return 0;
}

int deactivate_user(const char *username) {
    // remover ficheiro do utilizador
    char user_file[100];
    snprintf(user_file, sizeof(user_file), "./%s_file.csv", username);
    if (remove(user_file) != 0) {
        printf("Error deleting user file\n");
        return -1;
    }

    // remover fifo do utilizador
    char fifo_name[100];
    snprintf(fifo_name, sizeof(fifo_name), "%s_fifo", username);
    if (remove(fifo_name) != 0) {
        printf("Error deleting fifo\n");
        return -1;
    }

    // remover utilizador do grupo mta_users
    char group_command[100];
    snprintf(group_command, sizeof(group_command), "sudo usermod -G mta_users %s ", username);
    if (system(group_command) != 0) {
        printf("Error removing user from group\n");
        return -1;
    }

    printf("User deleted successfully\n");

    return 0;
}

int activate_user_request(const char *username) {
    int fd;
    User_request user_request;

    strcpy(user_request.username, username);
    user_request.flag = 0;

    fd = open("client_fifo", O_WRONLY);
    if (fd == -1) {
        perror("Erro ao abrir fifo client_handle\n");
        return -1;
    }

    if (write(fd, &user_request, sizeof(User_request)) == -1) {
        perror("Erro ao escrever no fifo\n");
        return -1;
    }

    close(fd);

    return 0;
}

int deactivate_user_request(const char *username) {
    int fd;
    User_request user_request;

    strcpy(user_request.username, username);
    user_request.flag = 1;

    fd = open("client_fifo", O_WRONLY);
    if (fd == -1) {
        perror("Erro ao abrir fifo client\n");
        return 1;
    }

    write(fd, &user_request, sizeof(User_request));

    close(fd);

    return 0;
}