# Stage 4 native adapter build

CC ?= cc
CFLAGS ?= -std=c99 -Os -Wall -Wextra -Werror -pedantic
CPPFLAGS ?=
BUILD := build
SOURCES := main.c sha256.c identifiers.c projector.c token_auth.c token_admin.c avtrans.c
HEADERS := sha256.h identifiers.h projector.h token_auth.h token_admin.h avtrans.h

.PHONY: host target clean

host: CPPFLAGS += -DPM3000_TESTING
host: $(BUILD)/pm3000-rest-host

$(BUILD)/pm3000-rest-host: $(SOURCES) $(HEADERS)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SOURCES)

target: CC := ../../components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-gcc
target: TARGET_STRIP := ../../components/dropbear/output-buildroot/host/bin/powerpc-buildroot-linux-musl-strip
target: CFLAGS += -static -mcpu=e300c3 -msoft-float
target: $(BUILD)/pm3000-rest-ppc32
	$(TARGET_STRIP) --strip-all $(BUILD)/pm3000-rest-ppc32

$(BUILD)/pm3000-rest-ppc32: $(SOURCES) $(HEADERS)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SOURCES)

clean:
	rm -rf $(BUILD)
