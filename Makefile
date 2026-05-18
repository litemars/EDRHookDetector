CC     := gcc

CFLAGS := -O2 -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security
CFLAGS += -Wshadow -Wconversion -Wno-sign-conversion
CFLAGS += -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -Isrc -Isrc/arch -Isrc/ebpf -Isrc/kernel

LDFLAGS := -ldl

TARGET := edr_hooks_check

SRCS := src/main.c src/common.c \
        src/arch/arch_arm64.c src/arch/arch_x86.c \
        src/ebpf/kernel_ebpf.c \
        src/kernel/kernel_hooks.c
OBJS := $(SRCS:.c=.o)

.PHONY: all static clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Static build (for portability)
static: LDFLAGS += -static
static: $(TARGET)

# Run the scanner (requires root for full scan)
run: $(TARGET)
	@if [ $$(id -u) -eq 0 ]; then \
		./$(TARGET); \
	else \
		echo "[*] Running as non-root, using self-scan mode"; \
		./$(TARGET) --self; \
	fi

# Scan specific PID
.PHONY: scan-pid
scan-pid: $(TARGET)
ifndef PID
	$(error PID is not set. Usage: make scan-pid PID=1234)
endif
	./$(TARGET) --pid $(PID) -v

clean:
	rm -f $(TARGET) $(OBJS)
