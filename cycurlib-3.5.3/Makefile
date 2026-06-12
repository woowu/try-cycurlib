# General options

CFLAGS = -Wall -Wextra -Wundef
ARFLAGS = r

CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

# Add include paths

CFLAGS += -Ilib/inc -Itests/inc

# CycurLIB library

LIB_BINARY = lib/bin/libcycurlib.a

LIB_SOURCES = $(wildcard lib/src/*.c)
LIB_OBJS = $(LIB_SOURCES:.c=.o)
LIB_DEPS = $(LIB_SOURCES:.c=.d)

# Self test library

TESTS_BINARY = tests/bin/libcycurlibtest.a

TESTS_SOURCES = $(wildcard tests/src/*.c)
TESTS_OBJS = $(TESTS_SOURCES:.c=.o)
TESTS_DEPS = $(TESTS_SOURCES:.c=.d)

# Targets

.PHONY: all clean lib tests

all: lib tests

lib: $(LIB_BINARY)

tests: $(TESTS_BINARY)

clean:
	rm -rf lib/src/*.o lib/src/*.d lib/bin/*
	rm -rf tests/src/*.o tests/src/*.d tests/bin/*

help:
	@echo 'CycurLIB makefile. The following targets are available:'
	@echo 'all    - build CycurLIB library and self-test library'
	@echo 'lib    - build CycurLIB library only'
	@echo 'tests  - build self-test library only'
	@echo 'clean  - clean previous build (remove any object files, library files and dependency files)'

$(LIB_BINARY): $(LIB_OBJS)
	$(AR) $(ARFLAGS) $(LIB_BINARY) $(LIB_OBJS)

$(TESTS_BINARY): $(TESTS_OBJS)
	$(AR) $(ARFLAGS) $(TESTS_BINARY) $(TESTS_OBJS)

%.o : %.c
	@$(CC) $(CFLAGS) -MM -MF $*.d -MT $@ $<
	$(CC) $(CFLAGS) -c $< -o $@

# Include dependency files

-include $(LIB_DEPS) $(TESTS_DEPS)
