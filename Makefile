PROG=ipk-sniffer

FILES=ipk-sniffer.c

CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror -pedantic

all:$(PROG)

$(PROG): $(FILES)
	$(CC) $(CFLAGS) -g -o $(PROG) $(FILES) -lpcap