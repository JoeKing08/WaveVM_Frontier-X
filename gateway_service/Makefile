CC = gcc
# 必须包含 -pthread 因为 aggregator.c 用到了多线程
CFLAGS = -Wall -O2 -I../common_include -pthread
TARGET = wavevm_gateway
SRCS = aggregator.c main.c 

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
