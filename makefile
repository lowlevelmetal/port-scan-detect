

CC = gcc
CFLAGS = -Wall -Wextra -pedantic -O2

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
EXEC := scan-detect

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXEC)
