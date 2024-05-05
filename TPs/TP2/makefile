CC = gcc
CFLAGS = -Wall -g
INC_DIR = include
SRC_DIR = src

all: client mta

client: $(SRC_DIR)/client.o $(SRC_DIR)/message.o $(SRC_DIR)/mta_groups.o $(SRC_DIR)/user_handle.o
	$(CC) $(CFLAGS) -o client $(SRC_DIR)/client.o $(SRC_DIR)/message.o $(SRC_DIR)/mta_groups.o $(SRC_DIR)/user_handle.o

mta: $(SRC_DIR)/mta.o $(SRC_DIR)/message.o $(SRC_DIR)/mta_groups.o $(SRC_DIR)/user_handle.o
	$(CC) $(CFLAGS) -o mta $(SRC_DIR)/mta.o $(SRC_DIR)/message.o $(SRC_DIR)/mta_groups.o $(SRC_DIR)/user_handle.o

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/message.h $(INC_DIR)/mta_groups.h $(INC_DIR)/user_handle.h
	$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<

clean:
	rm -f $(SRC_DIR)/*.o client mta mta_fifo mta_groups client_fifo