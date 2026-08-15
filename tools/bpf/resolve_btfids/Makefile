# SPDX-License-Identifier: GPL-2.0-only

srctree := $(abspath $(CURDIR)/../../../)
OUTPUT ?= $(if $(O),$(abspath $(O)),$(CURDIR))

HOSTCC ?= gcc
HOSTCFLAGS ?=
CFLAGS := $(HOSTCFLAGS) -O2 -g -Wall -Wextra -std=gnu11
CFLAGS += -idirafter $(srctree)/include/uapi
LDFLAGS ?=

TARGET := $(OUTPUT)/resolve_btfids

.PHONY: all clean

all: $(TARGET)

$(OUTPUT):
	mkdir -p $@

$(TARGET): $(srctree)/tools/bpf/resolve_btfids/main.c | $(OUTPUT)
	$(HOSTCC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lelf

clean:
	rm -f $(TARGET)
