# Stage 6 atomic publication helper

CC ?= cc
CFLAGS ?= -std=c99 -Os -Wall -Wextra -Werror -pedantic
BUILD := build
SOURCE := atomic-publish.c

.PHONY: host target clean

host: $(BUILD)/pm3000-atomic-publish-host

$(BUILD)/pm3000-atomic-publish-host: $(SOURCE)
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(SOURCE)

target: CC := ../../components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-gcc
target: TARGET_STRIP := ../../components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-strip
target: CFLAGS += -static -mcpu=e300c3 -msoft-float
target: $(BUILD)/pm3000-atomic-publish-ppc32
	$(TARGET_STRIP) --strip-all $<

$(BUILD)/pm3000-atomic-publish-ppc32: $(SOURCE)
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(SOURCE)

clean:
	rm -rf $(BUILD)
