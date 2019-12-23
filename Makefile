CC ?= gcc
CFLAGS += -Wall -Os
SERVER := notepad_server
CLIENT := notepad_client

.PHONY: all

all: $(SERVER) $(CLIENT)

$(SERVER): notepad_server.c utils.c
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

$(CLIENT): notepad_client.c utils.c
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

clean:
	rm $(SERVER)
	rm $(CLIENT)
