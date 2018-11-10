CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)gcc
CFLAGS ?= -W -Wall -std=gnu99 -D_GNU_SOURCE
LDFLAGS ?= -lssl -lcrypto

SRC := main.c bl2.c bl3.c amlcblk.c fip.c
OBJ := $(SRC:%.c=%.o)
BUILDDIR := build
DEPENDS := $(OBJ:%.o=$(BUILDDIR)/%.d)
PROG := gxlimg

ifeq ($(DEBUG), 1)
	CFLAGS += -DDEBUG=1 -g -O0
endif

define rm-file
	@(rm $(1) 2>/dev/null && \
		echo "rm $(1)") || true

endef

define rm-dir
	@(rmdir -p $(1) 2>/dev/null && \
		echo "rmdir -p $(1)") || true

endef

all: $(PROG)

$(PROG): $(OBJ:%=$(BUILDDIR)/%)
	$(LD) -o $@ $^ $(LDFLAGS)

$(BUILDDIR)/%.o: %.c | builddir
	$(CC) -MMD -c $(CFLAGS) -o $@ $<

builddir:
	@mkdir -p $(BUILDDIR)

.PHONY: clean distclean

clean:
	$(foreach o, $(OBJ:%=$(BUILDDIR)/%), $(call rm-file, $(o)))
	$(call rm-dir, $(BUILDDIR))

distclean: clean
	$(call rm-file, $(PROG))

-include ${DEPENDS}
