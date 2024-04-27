#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#define MAX_COMMAND_LENGTH 100

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
    printf("Running MTA\n");
    return 0;
}

int main() {
    printf("Welcome to MTA\n");

    while(1) {
        char command[MAX_COMMAND_LENGTH];
        printf("mta> ");
        fgets(command, MAX_COMMAND_LENGTH, stdin);
        command[strlen(command) - 1] = '\0';

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
            if (run() == 0) {
                printf("MTA mail service stopped running\n");
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
