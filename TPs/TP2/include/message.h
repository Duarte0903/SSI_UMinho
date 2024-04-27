#ifndef MESSAGE_H
#define MESSAGE_H

#define SUBJECT_SIZE 50
#define CONTENT_SIZE 512

typedef struct {
    char *sender;
    char *receiver;
    char subject[SUBJECT_SIZE];
    char content[CONTENT_SIZE];
} Message;

int send_msg();

#endif