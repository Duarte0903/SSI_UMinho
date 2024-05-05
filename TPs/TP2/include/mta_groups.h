#ifndef MTA_GROUPS_H
#define MTA_GROUPS_H

typedef struct {
    char sender[50];
    char groupname[50];
    int n_users;
    char users[50][50];
    int flag; // 0 - create group, 1 - delete group, 2 - add users to group, 3 - remove users from group
} Group_request;

void group_request_listener();
int create_group_request(const char *username);
int delete_group_request(const char *username);
int add_users_to_group(const char *username);
int remove_users_from_group(const char *username);
int group_inbox(const char *username);
int get_group_message_by_id(const char *username);

#endif