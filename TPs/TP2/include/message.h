#ifndef MESSAGE_H
#define MESSAGE_H

#define SENDER_SIZE 20
#define RECEIVER_SIZE 20
#define GROUP_SIZE 20
#define SUBJECT_SIZE 50
#define CONTENT_SIZE 512

typedef struct {
    char sender[SENDER_SIZE];
    char receiver[RECEIVER_SIZE];
    char group[GROUP_SIZE];
    char subject[SUBJECT_SIZE];
    char content[CONTENT_SIZE];
} Message;

int send_msg(const char *sender);
int send_grp_msg(const char *sender);
int serialize_message(char *buffer, const Message *msg, size_t buffer_size);
int deserialize_message(const char *buffer, Message *msg, size_t buffer_size);

#endif