CC = gcc
SERVER = notepad_server
CLIENT = notepad_client

.PHONY: all

all: $(SERVER) $(CLIENT)

$(SERVER): notepad_server.c utils.c
	$(CC) -o $@ $^ -lpthread

$(CLIENT): notepad_client.c utils.c
	$(CC) -o $@ $^ -lpthread

clean:
	rm $(SERVER)
	rm $(CLIENT)
