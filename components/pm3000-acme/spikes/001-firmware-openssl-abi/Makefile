REPO_ROOT := ../../../..
CROSS := $(REPO_ROOT)/components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-
CC := $(CROSS)gcc
LD := $(CROSS)ld
STRIP := $(CROSS)strip
READELF := $(CROSS)readelf
BUILD := build
STUBS := $(BUILD)/abi-stubs
TARGET := $(BUILD)/pm3000-acme-openssl-probe-ppc32
FIRMWARE_ROOT ?= /home/tseiman/agent-work/pm3000-firmware-analysis/rootfs
QEMU ?= qemu-ppc

.PHONY: all clean verify verify-qemu
all: $(TARGET)

$(BUILD)/probe.o: probe.c
	mkdir -p $(BUILD)
	$(CC) -c -std=c99 -Os -Wall -Wextra -Werror -pedantic \
		-fno-builtin -fno-stack-protector -fno-pic -mcpu=e300c3 -msoft-float \
		-nostdinc -o $@ $<

$(BUILD)/start.o: start.S
	mkdir -p $(BUILD)
	$(CC) -c -Os -fno-stack-protector -fno-pic -mcpu=e300c3 -msoft-float \
		-nostdinc -o $@ $<

$(STUBS)/libssl.so.1.0.0: abi-stubs/libssl-link.c
	mkdir -p $(STUBS)
	$(CC) -shared -nostdlib -fPIC -mcpu=e300c3 -msoft-float \
		-Wl,-soname,libssl.so.1.0.0 -o $@ $<

$(STUBS)/libcrypto.so.1.0.0: abi-stubs/libcrypto-link.c
	mkdir -p $(STUBS)
	$(CC) -shared -nostdlib -fPIC -mcpu=e300c3 -msoft-float \
		-Wl,-soname,libcrypto.so.1.0.0 -o $@ $<

$(STUBS)/libc.so.6: abi-stubs/libc-link.c abi-stubs/glibc-2.0.map
	mkdir -p $(STUBS)
	$(CC) -shared -nostdlib -fPIC -mcpu=e300c3 -msoft-float \
		-Wl,-soname,libc.so.6,--version-script=abi-stubs/glibc-2.0.map -o $@ $<

$(TARGET): $(BUILD)/start.o $(BUILD)/probe.o $(STUBS)/libssl.so.1.0.0 \
		$(STUBS)/libcrypto.so.1.0.0 $(STUBS)/libc.so.6
	$(LD) -m elf32ppclinux -z max-page-size=4096 --allow-shlib-undefined \
		-dynamic-linker /lib/ld.so.1 -e _start -o $@ \
		$(BUILD)/start.o $(BUILD)/probe.o \
		$(STUBS)/libssl.so.1.0.0 $(STUBS)/libcrypto.so.1.0.0 \
		`$(CC) -print-libgcc-file-name` $(STUBS)/libc.so.6
	$(STRIP) --strip-unneeded $@

verify: $(TARGET)
	file $(TARGET)
	$(READELF) -lW $(TARGET) | grep -F 'Requesting program interpreter: /lib/ld.so.1'
	$(READELF) -dW $(TARGET) | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | LC_ALL=C sort >$(BUILD)/needed.actual
	printf '%s\n' libc.so.6 libcrypto.so.1.0.0 libssl.so.1.0.0 >$(BUILD)/needed.expected
	cmp $(BUILD)/needed.expected $(BUILD)/needed.actual
	$(READELF) --wide --dyn-syms $(TARGET) | awk '$$7 == "UND" && $$8 != "" { print $$8 }' | LC_ALL=C sort -u >$(BUILD)/undefined.actual
	printf '%s\n' 'SSL_library_init' 'SSL_load_error_strings' 'SSLeay_version' 'write@GLIBC_2.0' >$(BUILD)/undefined.expected
	cmp $(BUILD)/undefined.expected $(BUILD)/undefined.actual
	wc -c <$(TARGET) | tr -d ' ' >$(BUILD)/size.bytes
	printf 'probe.size.bytes=%s\n' "$$(cat $(BUILD)/size.bytes)"
	printf '%s\n' 'spike.abi.verify.complete=yes'

verify-qemu: verify
	$(QEMU) -cpu e300c3 -L $(FIRMWARE_ROOT) $(TARGET) >$(BUILD)/probe.out
	grep -Fx 'openssl.version=OpenSSL 1.0.1l 15 Jan 2015' $(BUILD)/probe.out
	grep -Fx 'acme.openssl_abi.complete=yes' $(BUILD)/probe.out
	printf '%s\n' 'spike.qemu.verify.complete=yes'

clean:
	rm -rf $(BUILD)
