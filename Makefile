CC = $(CROSS_COMPILE)gcc
CYCURLIB=cycurlib-3.5.3

CPPFLAGS = -Wall -Wextra -Wundef \
		   -I$(CYCURLIB)/lib/inc -I$(CYCURLIB)/tests/inc
CFLAGS = -O0 -g

.PHONY: all clean

all: test-aes-gcm

%.o : %.c
	$(CC) $(CPPFLAGS) -c $< -o $@

test-aes-gcm: test-aes-gcm.o aes-gcm-stream-crypt.o memdump.o
	$(CC) $^ \
		$(CYCURLIB)/lib/bin/libcycurlib.a \
		$(CYCURLIB)/tests/bin/libcycurlibtest.a \
		-o $@

clean:
	@rm -rf test-aes-gcm *.o *~
