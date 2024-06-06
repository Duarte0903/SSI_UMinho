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
#include <grp.h>

#include "../include/message.h"
#include "../include/mta_groups.h"
#include "../include/user_handle.h"

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

int show_groups(const char *username) {
    printf("-------------------------------------------\n");

    printf("Grupos:\n");

    printf("-------------------------------------------\n");

    // Open the group file
    FILE *group_file = fopen("/etc/group", "r");
    if (group_file == NULL) {
        perror("fopen");
        return 1;
    }

    // Read each line of the group file
    struct group *grp;
    while ((grp = fgetgrent(group_file)) != NULL) {
        // Check if the user belongs to this group
        for (char **member = grp->gr_mem; *member != NULL; member++) {
            if (strcmp(*member, username) == 0) {
                printf("%s (%d)\n", grp->gr_name, grp->gr_gid);
                break;
            }
        }
    }

    printf("-------------------------------------------\n");

    // Close the group file
    fclose(group_file);

    return 0;
}

int show_group_members(const char *username) {
    char group_name[50];
    printf("Nome do grupo: ");
    scanf("%s", group_name);

    // ver se o grupo e mta_users
    if (strcmp(group_name, "mta_users") == 0) {
        printf("Não é possível mostrar membros do grupo mta_users\n");
        return -1;
    }

    // verificar se o grupo existe
    struct group *grp = getgrnam(group_name);
    if (grp == NULL) {
        printf("Grupo não encontrado\n");
        return -1;
    }

    // verificar se o utilizador pertence ao grupo
    int is_member = 0;
    for (char **member = grp->gr_mem; *member != NULL; member++) {
        if (strcmp(*member, username) == 0) {
            is_member = 1;
            break;
        }
    }
    if (!is_member) {
        printf("Utilizador não pertence ao grupo\n");
        return -1;
    }

    // mostrar membros do grupo
    printf("-------------------------------------------\n");
    printf("Membros do grupo %s:\n", group_name);
    printf("-------------------------------------------\n");
    for (char **member = grp->gr_mem; *member != NULL; member++) {
        printf("%s\n", *member);
    }
    printf("-------------------------------------------\n");

    return 0;
}

void message_listener(const char *username) {
    int fd;

    while (1) {
        char fifo_name[50];
        snprintf(fifo_name, sizeof(fifo_name), "%s_fifo", username);
        fd = open(fifo_name, O_RDONLY);
        if (fd == -1) {
            printf("Erro ao abrir fifo\n");
            return;
        }

        char buffer[MAX_MESSAGE_LENGTH];

        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));

        if (bytes_read == -1) {
            perror("Error reading from fifo\n");
            exit(EXIT_FAILURE);
        } else if (bytes_read == 0) {
            break;
        }

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
            _exit(0);
            close(fd);
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
        
        printf("Message ID: %s\n", field);
        field = strtok(NULL, DELIMITER);
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

int get_message_by_id(const char *username) {
    char inbox_path[50];
    snprintf(inbox_path, sizeof(inbox_path), "%s_file.csv", username);

    char message_id[50];
    printf("Message ID: ");
    scanf("%s", message_id);

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
        if (strcmp(field, message_id) == 0) {
            printf("-------------------------------------------\n");
            printf("Mensagem encontrada:\n");
            printf("-------------------------------------------\n");
            printf("Message ID: %s\n", field);
            field = strtok(NULL, DELIMITER);
            printf("Sender: %s\n", field);
            field = strtok(NULL, DELIMITER);
            printf("Receiver: %s\n", field);
            field = strtok(NULL, DELIMITER);
            printf("Subject: %s\n", field);
            field = strtok(NULL, DELIMITER);
            printf("Content: %s\n", field);
            printf("-------------------------------------------\n");
            break;
        }
    }

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

            else if (strcmp(command, "activate") == 0) {
                if (activate_user_request(username) == -1) {
                    printf("Erro ao ativar utilizador\n");
                }
            }

            else if (strcmp(command, "deactivate") == 0) {
                if (deactivate_user_request(username) == -1) {
                    printf("Erro ao desativar utilizador\n");
                }
            }

            else if (strcmp(command, "send_grp") == 0) {
                send_grp_msg(username);
            }

            else if (strcmp(command, "inbox") == 0) {
                if (inbox(username) == -1) {
                    printf("Erro ao mostrar inbox\n");
                }
            }

            else if (strcmp(command, "get_msg") == 0) {
                if (get_message_by_id(username) == -1) {
                    printf("Erro ao mostrar mensagem\n");
                }
            }

            else if (strcmp(command, "group_inbox") == 0) {
                if (group_inbox(username) == -1) {
                    printf("Erro ao mostrar inbox do grupo\n");
                }
            }

            else if (strcmp(command, "get_grp_msg") == 0) {
                if (get_group_message_by_id(username) == -1) {
                    printf("Erro ao mostrar mensagem do grupo\n");
                }
            }

            else if (strcmp(command, "groups") == 0) {
                if (show_groups(username) == -1) {
                    printf("Erro ao mostrar grupos\n");
                }
            }

            else if (strcmp(command, "group_members") == 0) {
                if (show_group_members(username) == -1) {
                    printf("Erro ao mostrar membros do grupo\n");
                }
            }

            else if (strcmp(command, "create_group") == 0) {
                if (create_group_request(username) == -1) {
                    printf("Erro ao criar grupo\n");
                }
            }

            else if (strcmp(command, "delete_group") == 0) {
                if (delete_group_request(username) == -1) {
                    printf("Erro ao eliminar grupo\n");
                }
            }

            else if (strcmp(command, "add_users_to_group") == 0) {
                if (add_users_to_group(username) == -1) {
                    printf("Erro ao adicionar utilizadores ao grupo\n");
                }
            }

            else if (strcmp(command, "remove_users_from_group") == 0) {
                if (remove_users_from_group(username) == -1) {
                    printf("Erro ao remover utilizadores do grupo\n");
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
                printf("send - enviar mensagem\n");
                printf("activate - ativar utilizador\n");
                printf("deactivate - desativar utilizador\n");
                printf("send_grp - enviar mensagem para grupo\n");
                printf("inbox - mostrar inbox\n");
                printf("get_msg - mostrar mensagem\n");
                printf("group_inbox - mostrar inbox do grupo\n");
                printf("get_grp_msg - mostrar mensagem do grupo\n");
                printf("groups - mostrar grupos\n");
                printf("group_members - mostrar membros do grupo\n");
                printf("create_group - criar grupo\n");
                printf("delete_group - eliminar grupo\n");
                printf("add_users_to_group - adicionar utilizadores ao grupo\n");
                printf("remove_users_from_group - remover utilizadores do grupo\n");
                printf("exit - sair\n");
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