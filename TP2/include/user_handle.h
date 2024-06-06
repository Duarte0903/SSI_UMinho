#ifndef USER_HANDLE_H
#define USER_HANDLE_H

typedef struct {
    char username[50];
    int flag; // 0 - activate user, 1 - delete user
} User_request;

void user_handler();
int activate_user(const char *username);
int deactivate_user(const char *username);
int activate_user_request(const char *username);
int deactivate_user_request(const char *username);

#endif