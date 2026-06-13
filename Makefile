CC = $(CROSS_COMPILE)gcc
CYCURLIB=cycurlib-3.5.3

CPPFLAGS = -Wall -Wextra -Wundef \
		   -I$(CYCURLIB)/lib/inc -I$(CYCURLIB)/tests/inc
CFLAGS = -O0 -g

.PHONY: all clean

all: aes-gcm-stream-codec

%.o : %.c
	$(CC) $(CPPFLAGS) -c $< -o $@

aes-gcm-stream-codec: aes-gcm-stream-codec.o memdump.o
	$(CC) $^ \
		$(CYCURLIB)/lib/bin/libcycurlib.a \
		$(CYCURLIB)/tests/bin/libcycurlibtest.a \
		-o $@

clean:
	@rm -rf aes-gcm-stream-codec *.o *~
