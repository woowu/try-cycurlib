CC = $(CROSS_COMPILE)gcc
CYCURLIB=cycurlib-3.5.3

CPPFLAGS = -Wall -Wextra -Wundef \
		   -I$(CYCURLIB)/lib/inc -I$(CYCURLIB)/tests/inc
CFLAGS = -O2 -g

.PHONY: all clean

all: test-aes-gcm

BINARIES = test-aes-gcm
SOURCES = $(wildcard *.c)
OBJS = $(SOURCES:.c=.o)
DEPS = $(SOURCES:.c=.d)

%.o : %.c
	@$(CC) $(CPPFLAGS) -MM -MF $*.d -MT $@ $<
	$(CC) $(CPPFLAGS) -c $< -o $@

test-aes-gcm: test-aes-gcm.o aes-gcm-stream-crypt.o memdump.o
	$(CC) $^ \
		$(CYCURLIB)/lib/bin/libcycurlib.a \
		$(CYCURLIB)/tests/bin/libcycurlibtest.a \
		-o $@

clean:
	@rm -rf test-aes-gcm *.o *.d *~

-include $(DEPS)
