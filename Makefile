CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)gcc
CFLAGS ?= -W -Wall -std=gnu99 -D_GNU_SOURCE
LDFLAGS ?= -lssl -lcrypto

SRC := main.c bl2.c bl3.c amlcblk.c amlsblk.c fip.c
OBJ := $(SRC:%.c=%.o)
BUILDDIR := build
DEPENDS := $(OBJ:%.o=$(BUILDDIR)/%.d)
PROG := gxlimg
FIPARCHIVE := libretech-cc_fip_20180418.tar.gz

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

$(BUILDDIR)/$(FIPARCHIVE):
	curl -L https://github.com/BayLibre/u-boot/releases/download/v2017.11-libretech-cc/$(FIPARCHIVE) -o $(BUILDDIR)/$(FIPARCHIVE)

fip-clean:
	@(rm -r $(BUILDDIR)/fip 2>/dev/null && \
		echo "rm -rf $(BUILDDIR)/fip") || true

ifdef FIP
fip: fip-clean
	cp -r "$(FIP)/" "$(BUILDDIR)/fip"
else
fip: $(BUILDDIR)/$(FIPARCHIVE) fip-clean
	tar -mxvzf $< -C $(BUILDDIR)
endif

$(BUILDDIR)/fip/gxl/bl2_acs.bin: fip
	python acs_tool.py $(BUILDDIR)/fip/gxl/bl2.bin \
		$@ $(BUILDDIR)/fip/gxl/acs.bin 0

$(BUILDDIR)/fip/gxl/bl2_new.bin: $(BUILDDIR)/fip/gxl/bl2_acs.bin fip
	$(BUILDDIR)/fip/blx_fix.sh $< zero_tmp \
		$(BUILDDIR)/fip/gxl/bl2_zero.bin $(BUILDDIR)/fip/gxl/bl21.bin \
		$(BUILDDIR)/fip/gxl/bl21_zero.bin $@ bl2

$(BUILDDIR)/fip/gxl/bl2.bin.enc: $(BUILDDIR)/fip/gxl/bl2_new.bin $(PROG)
	./$(PROG) -t bl2 -s $< $@

$(BUILDDIR)/fip/gxl/bl30_new.bin: fip
	$(BUILDDIR)/fip/blx_fix.sh $(BUILDDIR)/fip/gxl/bl30.bin zero_tmp \
	$(BUILDDIR)/fip/gxl/bl30_zero.bin $(BUILDDIR)/fip/gxl/bl301.bin \
	$(BUILDDIR)/fip/gxl/bl301_zero.bin $@ bl30

$(BUILDDIR)/fip/gxl/bl30.bin.enc: $(BUILDDIR)/fip/gxl/bl30_new.bin $(PROG)
	./$(PROG) -t bl3x -c $< $@

$(BUILDDIR)/fip/gxl/bl31.bin.enc: fip $(PROG)
	./$(PROG) -t bl3x -c $(BUILDDIR)/fip/gxl/bl31.img $@

$(BUILDDIR)/fip/gxl/u-boot.bin.enc: $(PROG) $(UBOOT)
ifdef UBOOT
	./$(PROG) -t bl3x -c "$(UBOOT)" $@
else
	$(error UBOOT variable is missing)
endif

$(BUILDDIR)/gxl-boot.bin: $(PROG) $(BUILDDIR)/fip/gxl/bl2.bin.enc $(BUILDDIR)/fip/gxl/bl30.bin.enc $(BUILDDIR)/fip/gxl/bl31.bin.enc $(BUILDDIR)/fip/gxl/u-boot.bin.enc
	./$(PROG) -t fip \
		--bl2 $(BUILDDIR)/fip/gxl/bl2.bin.enc \
		--bl30 $(BUILDDIR)/fip/gxl/bl30.bin.enc \
		--bl31 $(BUILDDIR)/fip/gxl/bl31.bin.enc \
		--bl33 $(BUILDDIR)/fip/gxl/u-boot.bin.enc \
		$@

image: $(BUILDDIR)/gxl-boot.bin

image-clean: fip-clean
	$(call rm-file, $(BUILDDIR)/$(FIPARCHIVE))
	$(call rm-file, $(BUILDDIR)/gxl-boot.bin)

builddir:
	@mkdir -p $(BUILDDIR)

.PHONY: clean distclean

clean: image-clean
	$(foreach o, $(OBJ:%=$(BUILDDIR)/%), $(call rm-file, $(o)))
	$(foreach d, $(DEPENDS), $(call rm-file, $(d)))
	$(call rm-dir, $(BUILDDIR))

distclean: clean
	$(call rm-file, $(PROG))

-include ${DEPENDS}
