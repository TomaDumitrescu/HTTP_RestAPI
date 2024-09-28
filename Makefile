CC=gcc
CFLAGS=-I.

client: client.c requests.c helpers.c buffer.c
	$(CC) -g -o client client.c requests.c helpers.c buffer.c parson.c -Wall -Wextra

run: client
	./client

pack:
	zip web_client.zip *.c *.h Makefile README

clean:
	rm -f *.o client
