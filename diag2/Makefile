CC = gcc
CFLAGS = -O2 -Wall -Wextra -maes -msse4 -march=native -mcmodel=large -no-pie
TARGET = test
SRCS = testsource.c aes_tdc.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

