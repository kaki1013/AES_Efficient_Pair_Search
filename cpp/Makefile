CXX = g++
CC  = gcc
CFLAGS = -O2 -Wall -Wextra -maes -msse4 -march=native -mcmodel=large -no-pie
TARGET = test
C_SRCS = aes_tdc.c
CPP_SRCS = testsource.cpp
OBJS = $(C_SRCS:.c=.o) $(CPP_SRCS:.cpp=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CFLAGS) -std=c++17 -c $< -o $@

clean:
	rm -f $(TARGET) *.o

