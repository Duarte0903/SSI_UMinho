CC = gcc
CFLAGS = -Wall -g
INC_DIR = include
SRC_DIR = src

all: client mta

client: $(SRC_DIR)/client.o $(SRC_DIR)/message.o 
	$(CC) $(CFLAGS) -o client $(SRC_DIR)/client.o $(SRC_DIR)/message.o

mta: $(SRC_DIR)/mta.o $(SRC_DIR)/message.o 
	$(CC) $(CFLAGS) -o mta $(SRC_DIR)/mta.o $(SRC_DIR)/message.o

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/message.h 
	$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<

clean:
	rm -f $(SRC_DIR)/*.o client mta