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
#include <sys/stat.h>
#include <syslog.h>

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

int create_group() {
    char groupname[20];

    printf("Enter group name: ");
    scanf("%s", groupname);

    // criar novo grupo
    char group_add_command[100];
    snprintf(group_add_command, sizeof(group_add_command), "sudo groupadd %s", groupname);
    if (system(group_add_command) != 0) {
        printf("Error creating group\n");
        return -1;
    }

    printf("Group created successfully\n");

    return 0;
}

int add_to_group() {
    char username[20];
    char groupname[20];

    printf("Enter username: ");
    scanf("%s", username);

    printf("Enter group name: ");
    scanf("%s", groupname);

    // adicionar utilizador ao grupo
    char group_command[100];
    snprintf(group_command, sizeof(group_command), "sudo usermod -a -G %s %s", groupname, username);
    if (system(group_command) != 0) {
        printf("Error adding user to group\n");
        return -1;
    }

    printf("User added to group successfully\n");

    return 0;
}

int remove_from_group() {
    char username[20];
    char groupname[20];

    printf("Enter username: ");
    scanf("%s", username);

    printf("Enter group name: ");
    scanf("%s", groupname);

    // remover utilizador do grupo
    char group_command[100];
    snprintf(group_command, sizeof(group_command), "sudo gpasswd -d %s %s", username, groupname);
    if (system(group_command) != 0) {
        printf("Error removing user from group\n");
        return -1;
    }

    printf("User removed from group successfully\n");

    return 0;
}

int delete_group() {
    char groupname[20];

    printf("Enter group name: ");
    scanf("%s", groupname);

    // remover grupo
    char group_delete_command[100];
    snprintf(group_delete_command, sizeof(group_delete_command), "sudo groupdel %s", groupname);
    if (system(group_delete_command) != 0) {
        printf("Error deleting group\n");
        return -1;
    }

    printf("Group deleted successfully\n");

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

    while (1) {
        char buffer[MAX_MESSAGE_LENGTH];

        ssize_t bytes_read = read(fifo_fd, buffer, sizeof(buffer));

        if (bytes_read == -1) {
            perror("Error reading from fifo\n");
            close(fifo_fd);
            return -1;
        } else if (bytes_read == 0) {
            break;
        }

        Message received_msg;

        if (deserialize_message(buffer, &received_msg, sizeof(buffer)) != 0) {
            printf("Error deserializing message\n");
            close(fifo_fd);
            return -1;
        }

        printf("Message received from %s\n", received_msg.sender);

        if (strlen(received_msg.receiver) > 0) {
            pid_t pid = fork();

            if (pid == -1) {
                perror("Error forking\n");
                close(fifo_fd);
                return -1;
            }

            if (pid == 0) {
                char user_file[100];
                snprintf(user_file, sizeof(user_file), "./%s_file.csv", received_msg.receiver);
                FILE *file = fopen(user_file, "a");
                if (file == NULL) {
                    printf("Error opening user file\n");
                    close(fifo_fd);
                    return -1;
                }

                time_t now = time(NULL);
                struct tm *tm = localtime(&now);
                char timestamp[20];
                strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

                fprintf(file, "%s;%s;%s;%s;%s\n", received_msg.sender, received_msg.receiver, received_msg.subject, received_msg.content, timestamp);
                fclose(file);

                printf("Message saved to %s's file\n", received_msg.receiver);
                exit(0);
            }

            int status; 
            waitpid(pid, &status, 0);
        }

        else if (strlen(received_msg.group) > 0 && strlen(received_msg.receiver) == 0) {
            pid_t pid = fork();

            if (pid == -1) {
                perror("Error forking\n");
                close(fifo_fd);
                return -1;
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

                char command[100];
                snprintf(command, sizeof(command), "getent group %s | grep -w %s | grep -q '\\b%s\\b'", received_msg.group, received_msg.group, received_msg.sender);
                if (system(command) != 0) {
                    printf("Error: sender does not belong to group\n");
                    exit(-1);
                }

                users = grp->gr_mem;

                if (*users == NULL) {
                    printf("Error: group has no members\n");
                    exit(-1);
                }

                while (*users != NULL) {
                    pid_t pid = fork();

                    if (pid == -1) {
                        perror("Error forking\n");
                        return -1;
                    }

                    if (pid == 0) {
                        printf("saving message to %s's file\n", *users);

                        char user_file[100];
                        snprintf(user_file, sizeof(user_file), "./%s_file.csv", *users);
                        FILE *file = fopen(user_file, "a");
                        if (file == NULL) {
                            printf("Error opening user file\n");
                        }

                        time_t now = time(NULL);
                        struct tm *tm = localtime(&now);
                        char timestamp[20];
                        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

                        fprintf(file, "%s;%s;%s;%s;%s\n", received_msg.sender, *users, received_msg.subject, received_msg.content, timestamp);
                        fclose(file);

                        printf("Message saved to %s's file\n", *users);
                        exit(0);
                    }

                    int status; 
                    waitpid(pid, &status, 0);

                    users++;
                }
            }

            int status;
            waitpid(pid, &status, 0);
        }
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

        else if (strcmp(command, "create_group") == 0) {
            if (create_group() != 0) {
                printf("Error creating group\n");
            }
        }

        else if (strcmp(command, "add_to_group") == 0) {
            if (add_to_group() != 0) {
                printf("Error adding user to group\n");
            }
        }

        else if (strcmp(command, "remove_from_group") == 0) {
            if (remove_from_group() != 0) {
                printf("Error removing user from group\n");
            }
        }

        else if (strcmp(command, "delete_group") == 0) {
            if (delete_group() != 0) {
                printf("Error deleting group\n");
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
            printf("create_group - creates a new group\n");
            printf("add_to_group - adds user to a group\n");
            printf("remove_from_group - removes user from a group\n");
            printf("delete_group - deletes a group\n");
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
