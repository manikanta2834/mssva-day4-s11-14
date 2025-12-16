CC=clang
CFLAGS=-g -O0 -Wall -Iinclude

all: dataproc-agent-instrumented

dataproc-agent-instrumented:
	$(CC) $(CFLAGS) src/*.c -o dataproc-agent-instrumented

asan:
	$(CC) $(CFLAGS) -fsanitize=address src/*.c -o dataproc-agent-instrumented

ubsan:
	$(CC) $(CFLAGS) -fsanitize=undefined src/*.c -o dataproc-agent-instrumented

clean:
	rm -f dataproc-agent-instrumented
