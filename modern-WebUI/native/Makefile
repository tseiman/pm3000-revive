# Stage 4 native adapter build

CC ?= cc
CFLAGS ?= -std=c99 -Os -Wall -Wextra -Werror -pedantic
CPPFLAGS ?=
BUILD := build
SOURCES := main.c sha256.c identifiers.c projector.c token_auth.c token_admin.c controller_xml.c fixed_form.c avtrans.c session.c service_session.c acme_admin_client.c acme_settings.c
HEADERS := sha256.h identifiers.h projector.h token_auth.h token_admin.h controller_xml.h fixed_form.h avtrans.h session.h service_session.h acme_admin_client.h acme_settings.h
CROSS := ../../components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-
TARGET_CC := $(CROSS)gcc
TARGET_LD := $(CROSS)ld
TARGET_STRIP := $(CROSS)strip
GSP_HELPER := $(BUILD)/pm3000-gsp-session-helper-ppc32
ACME_ADMIN := $(BUILD)/pm3000-acme-admin-ppc32
GSP_OBJECT := $(BUILD)/gsp-session-helper.o
GSP_START := $(BUILD)/gsp-ppc-start.o
ABI_STUB_SOURCE := abi-stubs
ABI_STUB_BUILD := $(BUILD)/abi-stubs
GSP_LINK_STUB := $(ABI_STUB_BUILD)/libgsp_auth.so
LIBC_LINK_STUB := $(ABI_STUB_BUILD)/libc.so.6

.PHONY: host target clean

host: CPPFLAGS += -DPM3000_TESTING
host: $(BUILD)/pm3000-rest-host

$(BUILD)/pm3000-rest-host: $(SOURCES) $(HEADERS)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SOURCES)

target: CC := $(TARGET_CC)
target: CFLAGS += -static -mcpu=e300c3 -msoft-float -ffunction-sections -fdata-sections -Wl,--gc-sections
target: $(BUILD)/pm3000-rest-ppc32 $(GSP_HELPER) $(ACME_ADMIN)
	$(TARGET_STRIP) --strip-all $(BUILD)/pm3000-rest-ppc32
	$(TARGET_STRIP) --strip-unneeded $(GSP_HELPER)
	$(TARGET_STRIP) --strip-all $(ACME_ADMIN)

$(BUILD)/pm3000-rest-ppc32: $(SOURCES) $(HEADERS)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SOURCES)

$(ACME_ADMIN): pm3000-acme-admin.c
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(GSP_OBJECT): gsp-session-helper.c
	mkdir -p $(BUILD)
	$(CC) -c -std=c99 -Os -Wall -Wextra -Werror -fno-stack-protector -fno-pic \
		-mcpu=e300c3 -msoft-float -nostdinc -o $@ $<

$(GSP_START): gsp-ppc-start.S
	mkdir -p $(BUILD)
	$(CC) -c -Os -fno-stack-protector -fno-pic -mcpu=e300c3 -msoft-float \
		-nostdinc -o $@ $<

$(GSP_LINK_STUB): $(ABI_STUB_SOURCE)/libgsp-auth-link.c
	mkdir -p $(ABI_STUB_BUILD)
	$(TARGET_CC) -shared -nostdlib -fPIC -mcpu=e300c3 -msoft-float \
		-Wl,-soname,libgsp_auth.so -o $@ $<

$(LIBC_LINK_STUB): $(ABI_STUB_SOURCE)/libc-glibc20-link.c $(ABI_STUB_SOURCE)/glibc-2.0.map
	mkdir -p $(ABI_STUB_BUILD)
	$(TARGET_CC) -shared -nostdlib -fPIC -mcpu=e300c3 -msoft-float \
		-Wl,-soname,libc.so.6,--version-script=$(ABI_STUB_SOURCE)/glibc-2.0.map -o $@ $<

$(GSP_HELPER): $(GSP_OBJECT) $(GSP_START) $(GSP_LINK_STUB) $(LIBC_LINK_STUB)
	$(TARGET_LD) -m elf32ppclinux -z max-page-size=4096 --allow-shlib-undefined -dynamic-linker /lib/ld.so.1 \
		-e _start -o $@ $(GSP_START) $(GSP_OBJECT) \
		`$(CC) -print-libgcc-file-name` \
		$(GSP_LINK_STUB) $(LIBC_LINK_STUB)

clean:
	rm -rf $(BUILD)
