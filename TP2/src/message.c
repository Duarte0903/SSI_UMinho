#include <stdio.h>
#include <unistd.h>  
#include <sys/types.h> 
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "message.h"

#define MAX_MESSAGE_LENGTH sizeof(Message)

int serialize_message(char *buffer, const Message *msg, size_t buffer_size) {
    if (buffer_size < MAX_MESSAGE_LENGTH) {
        return -1;
    }

    memcpy(buffer, msg, MAX_MESSAGE_LENGTH);

    return 0;
}

int deserialize_message(const char *buffer, Message *msg, size_t buffer_size) {
    if (buffer_size < MAX_MESSAGE_LENGTH) {
        return -1;
    }

    memcpy(msg, buffer, MAX_MESSAGE_LENGTH);

    return 0;
}

int send_msg(const char *sender) {
    Message msg;

    strcpy(msg.sender, sender);
    
    printf("Destinatário: ");
    scanf("%s", msg.receiver);

    printf("Assunto: ");
    scanf(" %[^\n]", msg.subject);

    printf("Mensagem: ");
    scanf(" %[^\n]", msg.content);

    strcpy(msg.group, "");

    char buffer[MAX_MESSAGE_LENGTH];
    if (serialize_message(buffer, &msg, sizeof(buffer)) != 0) {
        printf("Error serializing message\n");
        return -1;
    }

    int mta_fifo = open("mta_fifo", O_WRONLY);
    if (mta_fifo == -1) {
        perror("Error opening fifo\n");
        return -1;
    }

    if (write(mta_fifo, buffer, sizeof(buffer)) == -1) {
        perror("Error writing to fifo\n");
        return -1;
    }

    printf("Message sent to MTA\n");

    return 0;
}

int send_grp_msg(const char *sender) {
    Message msg;

    strcpy(msg.sender, sender);

    strcpy(msg.receiver, "");
    
    printf("Grupo: ");
    scanf("%s", msg.group);

    printf("Assunto: ");
    scanf(" %[^\n]", msg.subject);

    printf("Mensagem: ");
    scanf(" %[^\n]", msg.content);

    char buffer[MAX_MESSAGE_LENGTH];
    if (serialize_message(buffer, &msg, sizeof(buffer)) != 0) {
        printf("Error serializing message\n");
        return -1;
    }

    int mta_fifo = open("mta_fifo", O_WRONLY);
    if (mta_fifo == -1) {
        perror("Error opening fifo\n");
        return -1;
    }

    if (write(mta_fifo, buffer, sizeof(buffer)) == -1) {
        perror("Error writing to fifo\n");
        return -1;
    }

    printf("Message sent to MTA\n");

    return 0;
}