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
#include <pwd.h>

#include "../include/message.h"
#include "../include/mta_groups.h"

#define MAX_MESSAGE_LENGTH sizeof(Message)
#define MAX_LINE_LENGTH 1024 
#define MAX_FIELDS 10        
#define DELIMITER ";" 

void group_request_listener() {
    int fd;

    while (1) {
        fd = open("mta_groups", O_RDONLY);
        if (fd == -1) {
            perror("Erro ao abrir fifo");
            return;
        }
        
        char buffer[sizeof(Group_request)];

        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));

        if (bytes_read == -1) {
            perror("Error reading from fifo\n");
        } else if (bytes_read == 0) {
            break;
        }
        
        Group_request group_request;

        memcpy(&group_request, buffer, sizeof(Group_request));

        printf("Pedido recebido de %s\n", group_request.sender);

        pid_t pid = fork();

        if (pid < 0) {
            printf("Erro ao criar processo\n");
            return;
        }

        if (pid == 0) {
            // criar grupo (flag = 0)
            if (group_request.flag == 0) {
                printf("A criar grupo %s ...\n", group_request.groupname);

                // verificar se o sender pertence ao grupo mta_users
                struct group *grp = getgrnam("mta_users");
                int is_member = 0;
                for (int i = 0; grp->gr_mem[i] != NULL; i++) {
                    if (strcmp(grp->gr_mem[i], group_request.sender) == 0) {
                        is_member = 1;
                        break;
                    }
                }
                if (!is_member) {
                    printf("Utilizador %s não pertence ao grupo mta_users\n", group_request.sender);
                    _exit(-1);
                }

                // verificar se o grupo já existe
                if (getgrnam(group_request.groupname) != NULL) {
                    printf("Grupo %s já existe\n", group_request.groupname);
                    _exit(-1);
                } else {
                    char group_add_command[200];
                    snprintf(group_add_command, sizeof(group_add_command), "sudo groupadd %s", group_request.groupname);
                    if (system(group_add_command) != 0) {
                        printf("Error creating group\n");
                        _exit(-1);
                    }
                }

                // adicionar utilizadores ao grupo
                for (int i = 0; i < group_request.n_users; i++) {
                    char group_command[200];
                    snprintf(group_command, sizeof(group_command), "sudo usermod -a -G %s %s", group_request.groupname, group_request.users[i]);
                    if (system(group_command) != 0) {
                        printf("Error adding user to group\n");
                    }
                    printf("Utilizador %s adicionado ao grupo %s\n", group_request.users[i], group_request.groupname);
                }

                // criar a inbox do grupo
                char group_file[100];
                snprintf(group_file, sizeof(group_file), "./%s_group_file.csv", group_request.groupname);
                FILE *file = fopen(group_file, "w");
                if (file == NULL) {
                    printf("Error creating group file\n");
                    _exit(-1);
                }
                fprintf(file, "id;sender;receiver;subject;content;time-stamp\n");
                fclose(file);

                // gerir permissões do ficheiro com chmod
                char chmod_command[200];
                snprintf(chmod_command, sizeof(chmod_command), "sudo chmod 660 %s", group_file);
                if (system(chmod_command) != 0) {
                    printf("Error changing file permissions\n");
                    _exit(-1);
                }

                printf("Grupo %s criado com sucesso\n", group_request.groupname);
            }

            // eliminar grupo (flag = 1)
            else if (group_request.flag == 1) {
                printf("A eliminar grupo %s ...\n", group_request.groupname);

                // verificar se o nome do grupo é mta_users
                if (strcmp(group_request.groupname, "mta_users") == 0) {
                    printf("Não é possível eliminar o grupo mta_users\n");
                    _exit(-1);
                }

                // verificar se o sender do pedido é o primeiro membro do grupo
                struct group *grp = getgrnam(group_request.groupname);
                if (grp != NULL && grp->gr_mem[0] != NULL) {
                    if (strcmp(grp->gr_mem[0], group_request.sender) != 0) {
                        printf("Utilizador %s não é o primeiro membro do grupo %s\n", group_request.sender, group_request.groupname);
                        _exit(-1);
                    }
                } else {
                    printf("Grupo %s não encontrado ou sem membros\n", group_request.groupname);
                    _exit(-1);
                }
                printf("Utilizador %s é o primeiro membro do grupo %s\n", group_request.sender, group_request.groupname);

                // verificar se o sender pertence ao grupo mta_users
                struct group *grp_mta = getgrnam("mta_users");
                int is_member = 0;
                for (int i = 0; grp_mta->gr_mem[i] != NULL; i++) {
                    if (strcmp(grp_mta->gr_mem[i], group_request.sender) == 0) {
                        is_member = 1;
                        break;
                    }
                }
                if (!is_member) {
                    printf("Utilizador %s não pertence ao grupo mta_users\n", group_request.sender);
                    _exit(-1);
                }

                // eliminar utilizadores do grupo
                char group_del_command[200];
                snprintf(group_del_command, sizeof(group_del_command), "sudo groupdel %s", group_request.groupname);
                if (system(group_del_command) != 0) {
                    printf("Error deleting group\n");
                }

                // eliminar o ficheiro do grupo
                char group_file[100];
                snprintf(group_file, sizeof(group_file), "./%s_group_file.csv", group_request.groupname);
                if (remove(group_file) != 0) {
                    printf("Error deleting group file\n");
                }

                printf("Grupo %s eliminado com sucesso\n", group_request.groupname);
            }
        
            // adicionar utilizadores a um grupo (flag = 2)
            else if (group_request.flag == 2) {
                printf("A adicionar utilizadores ao grupo %s ...\n", group_request.groupname);

                // verificar se o sender do pedido é o primeiro membro do grupo
                struct group *grp = getgrnam(group_request.groupname);
                if (grp != NULL && grp->gr_mem[0] != NULL) {
                    if (strcmp(grp->gr_mem[0], group_request.sender) != 0) {
                        printf("Utilizador %s não é o primeiro membro do grupo %s\n", group_request.sender, group_request.groupname);
                        _exit(-1);
                    }
                } else {
                    printf("Grupo %s não encontrado ou sem membros\n", group_request.groupname);
                    _exit(-1);
                }
                printf("Utilizador %s é o primeiro membro do grupo %s\n", group_request.sender, group_request.groupname);

                // verificar se o sender pertence ao grupo mta_users
                struct group *grp_mta = getgrnam("mta_users");
                int is_member = 0;
                for (int i = 0; grp_mta->gr_mem[i] != NULL; i++) {
                    if (strcmp(grp_mta->gr_mem[i], group_request.sender) == 0) {
                        is_member = 1;
                        break;
                    }
                }
                if (!is_member) {
                    printf("Utilizador %s não pertence ao grupo mta_users\n", group_request.sender);
                    _exit(-1);
                }

                // adicionar utilizadores ao grupo
                for (int i = 0; i < group_request.n_users; i++) {
                    char group_command[200];
                    snprintf(group_command, sizeof(group_command), "sudo usermod -a -G %s %s", group_request.groupname, group_request.users[i]);
                    if (system(group_command) != 0) {
                        printf("Error adding user to group\n");
                    }
                    printf("Utilizador %s adicionado ao grupo %s\n", group_request.users[i], group_request.groupname);
                }

                printf("Utilizadores adicionados ao grupo %s\n", group_request.groupname);
            }

            // remover utilizadores de um grupo (flag = 3)
            else if (group_request.flag == 3) {
                printf("A remover utilizadores do grupo %s ...\n", group_request.groupname);

                // verificar se o sender do pedido é o primeiro membro do grupo
                struct group *grp = getgrnam(group_request.groupname);
                if (grp != NULL && grp->gr_mem[0] != NULL) {
                    if (strcmp(grp->gr_mem[0], group_request.sender) != 0) {
                        printf("Utilizador %s não é o primeiro membro do grupo %s\n", group_request.sender, group_request.groupname);
                        _exit(-1);
                    }
                } else {
                    printf("Grupo %s não encontrado ou sem membros\n", group_request.groupname);
                    _exit(-1);
                }
                printf("Utilizador %s é o primeiro membro do grupo %s\n", group_request.sender, group_request.groupname);

                // verificar se o sender pertence ao grupo mta_users
                struct group *grp_mta = getgrnam("mta_users");
                int is_member = 0;
                for (int i = 0; grp_mta->gr_mem[i] != NULL; i++) {
                    if (strcmp(grp_mta->gr_mem[i], group_request.sender) == 0) {
                        is_member = 1;
                        break;
                    }
                }
                if (!is_member) {
                    printf("Utilizador %s não pertence ao grupo mta_users\n", group_request.sender);
                    _exit(-1);
                }

                // remover utilizadores do grupo
                for (int i = 0; i < group_request.n_users; i++) {
                    char group_command[200];
                    snprintf(group_command, sizeof(group_command), "sudo gpasswd -d %s %s", group_request.users[i], group_request.groupname);
                    if (system(group_command) != 0) {
                        printf("Error removing user from group\n");
                    }
                    printf("Utilizador %s removido do grupo %s\n", group_request.users[i], group_request.groupname);
                }

                printf("Utilizadores removidos do grupo %s\n", group_request.groupname);
            }

            _exit(0);
        }

        int status;
        waitpid(pid, &status, 0);
        close(fd);
    }

    close(fd);
}

int create_group_request(const char *username) {
    Group_request group_request;
    strcpy(group_request.sender, username);

    int fd;
    fd = open("mta_groups", O_WRONLY);
    if (fd == -1) {
        perror("Erro ao abrir fifo mta_groups");
        return -1;
    }

    printf("Nome do grupo: ");
    scanf(" %[^\n]", group_request.groupname);

    // verificar se o grupo e mt_users
    if (strcmp(group_request.groupname, "mta_users") == 0) {
        printf("Não é possível usar mta_users\n");
        return -1;
    }

    printf("Número de utilizadores (a contar com o criador): ");
    scanf("%d", &group_request.n_users);

    // adicionar o criador do grupo
    strcpy(group_request.users[0], username);

    printf("Utilizador 1: %s\n", group_request.users[0]);

    for (int i = 1; i < group_request.n_users; i++) {
        char user[50];
        printf("Utilizador %d: ", i + 1);
        scanf("%s", user);
        strcpy(group_request.users[i], user);
    }

    // flag para indicar que é um pedido de criação de grupo
    group_request.flag = 0;

    // enviar pedido para o mta
    if (write(fd, &group_request, sizeof(Group_request)) == -1) {
        perror("Erro ao escrever no fifo");
        return -1;
    }

    close(fd);

    return 0;
}

int delete_group_request(const char *username) {
    Group_request group_request;
    strcpy(group_request.sender, username);

    int fd;
    fd = open("mta_groups", O_WRONLY);
    if (fd == -1) {
        perror("Erro ao abrir fifo");
        return -1;
    }

    printf("Nome do grupo: ");
    scanf(" %[^\n]", group_request.groupname);

    // verificar se o grupo e mt_users
    if (strcmp(group_request.groupname, "mta_users") == 0) {
        printf("Não é possível usar mta_users\n");
        return -1;
    }

    // flag para indicar que é um pedido de eliminação de grupo
    group_request.flag = 1;

    // enviar pedido para o mta
    if (write(fd, &group_request, sizeof(Group_request)) == -1) {
        perror("Erro ao escrever no fifo");
        return -1;
    }

    close(fd);

    return 0;
}

int add_users_to_group(const char *username) {
    Group_request group_request;
    strcpy(group_request.sender, username);

    printf("Nome do grupo: ");
    scanf(" %[^\n]", group_request.groupname);

    // verificar se o grupo e mt_users
    if (strcmp(group_request.groupname, "mta_users") == 0) {
        printf("Não é possível usar mta_users\n");
        return -1;
    }

    printf("Número de utilizadores a adicionar: ");
    scanf("%d", &group_request.n_users);

    for (int i = 0; i < group_request.n_users; i++) {
        char user[50];
        printf("Utilizador %d: ", i + 1);
        scanf("%s", user);
        strcpy(group_request.users[i], user);
    }

    // flag para indicar que é um pedido de adição de utilizadores a um grupo
    group_request.flag = 2;

    // enviar pedido para o mta
    int fd;
    fd = open("mta_groups", O_WRONLY);
    if (fd == -1) {
        perror("Erro ao abrir fifo");
        return -1;
    }

    if (write(fd, &group_request, sizeof(Group_request)) == -1) {
        perror("Erro ao escrever no fifo");
        return -1;
    }

    close(fd);

    return 0;
}

int remove_users_from_group(const char *username) {
    Group_request group_request;
    strcpy(group_request.sender, username);

    printf("Nome do grupo: ");
    scanf(" %[^\n]", group_request.groupname);

    // verificar se o grupo e mt_users
    if (strcmp(group_request.groupname, "mta_users") == 0) {
        printf("Não é possível usar mta_users\n");
        return -1;
    }

    printf("Número de utilizadores a remover: ");
    scanf("%d", &group_request.n_users);

    for (int i = 0; i < group_request.n_users; i++) {
        char user[50];
        printf("Utilizador %d: ", i + 1);
        scanf("%s", user);
        strcpy(group_request.users[i], user);
    }

    // flag para indicar que é um pedido de remoção de utilizadores de um grupo
    group_request.flag = 3;

    // enviar pedido para o mta
    int fd;
    fd = open("mta_groups", O_WRONLY);
    if (fd == -1) {
        perror("Erro ao abrir fifo");
        return -1;
    }

    if (write(fd, &group_request, sizeof(Group_request)) == -1) {
        perror("Erro ao escrever no fifo");
        return -1;
    }

    close(fd);

    return 0;
}

int group_inbox(const char *username) {
    char groupname[50];
    printf("Nome do grupo: ");
    scanf(" %[^\n]", groupname);

    // verificar se o grupo e mt_users
    if (strcmp(groupname, "mta_users") == 0) {
        printf("Não é possível aceder à inbox do grupo mta_users\n");
        return -1;
    }

    // verificar se o utilizador pertence ao grupo
    struct group *grp = getgrnam(groupname);
    int is_member = 0;
    for (int i = 0; grp->gr_mem[i] != NULL; i++) {
        if (strcmp(grp->gr_mem[i], username) == 0) {
            is_member = 1;
            break;
        }
    }
    if (!is_member) {
        printf("Utilizador %s não pertence ao grupo %s\n", username, groupname);
        return -1;
    }

    char group_file[100];
    snprintf(group_file, sizeof(group_file), "./%s_group_file.csv", groupname);

    FILE *file = fopen(group_file, "r");
    if (file == NULL) {
        printf("Ficheiro do grupo %s não encontrado\n", groupname);
        return -1;
    }

    printf("-------------------------------------------\n");

    printf("%s Inbox:\n", groupname);

    printf("-------------------------------------------\n");

    char line[MAX_LINE_LENGTH];
    int first_line_skipped = 0;
    while (fgets(line, sizeof(line), file)) {
        if (!first_line_skipped) {
            first_line_skipped = 1;
            continue;
        }
        line[strcspn(line, "\n")] = '\0';
        
        char *field = strtok(line, DELIMITER);
        
        printf("Message ID: %s\n", field);
        field = strtok(NULL, DELIMITER);
        printf("Sender: %s\n", field);
        field = strtok(NULL, DELIMITER);
        printf("Grupo: %s\n", field);
        field = strtok(NULL, DELIMITER);
        printf("Subject: %s\n", field);
        field = strtok(NULL, DELIMITER);
        printf("Content: %s\n", field);
        
        printf("-------------------------------------------\n");
    }

    fclose(file);

    return 0;
}

int get_group_message_by_id(const char *username) {
    char groupname[50];
    printf("Nome do grupo: ");
    scanf(" %[^\n]", groupname);

    // verificar se o grupo e mt_users
    if (strcmp(groupname, "mta_users") == 0) {
        printf("Não é possível aceder à inbox do grupo mta_users\n");
        return -1;
    }

    // verificar se o utilizador pertence ao grupo
    struct group *grp = getgrnam(groupname);
    int is_member = 0;
    for (int i = 0; grp->gr_mem[i] != NULL; i++) {
        if (strcmp(grp->gr_mem[i], username) == 0) {
            is_member = 1;
            break;
        }
    }
    if (!is_member) {
        printf("Utilizador %s não pertence ao grupo %s\n", username, groupname);
        return -1;
    }

    char group_file[100];
    snprintf(group_file, sizeof(group_file), "./%s_group_file.csv", groupname);

    FILE *file = fopen(group_file, "r");
    if (file == NULL) {
        printf("Ficheiro do grupo %s não encontrado\n", groupname);
        return -1;
    }

    char id[10];
    printf("ID da mensagem: ");
    scanf("%s", id);

    char line[MAX_LINE_LENGTH];
    int first_line_skipped = 0;
    while (fgets(line, sizeof(line), file)) {
        if (!first_line_skipped) {
            first_line_skipped = 1;
            continue;
        }
        line[strcspn(line, "\n")] = '\0';
        
        char *field = strtok(line, DELIMITER);
        if (strcmp(field, id) == 0) {
            printf("-------------------------------------------\n");
            printf("Mensagem encontrada:\n");
            printf("-------------------------------------------\n");
            printf("Message ID: %s\n", field);
            field = strtok(NULL, DELIMITER);
            printf("Sender: %s\n", field);
            field = strtok(NULL, DELIMITER);
            printf("Grupo: %s\n", field);
            field = strtok(NULL, DELIMITER);
            printf("Subject: %s\n", field);
            field = strtok(NULL, DELIMITER);
            printf("Content: %s\n", field);
            printf("-------------------------------------------\n");
            break;
        }
    }

    fclose(file);

    return 0;
}