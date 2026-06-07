CC     := gcc

CFLAGS := -O2 -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security
CFLAGS += -Wshadow -Wconversion -Wno-sign-conversion
CFLAGS += -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -Isrc -Isrc/arch -Isrc/ebpf -Isrc/kernel

# Auto-generate per-object header dependencies so editing a .h triggers
# rebuilds of every .c that includes it.
DEPFLAGS := -MMD -MP
CFLAGS   += $(DEPFLAGS)

# The scanner makes no dlopen/dlsym calls of its own, so it needs no extra
# libraries. Keeping this empty also lets `make static` link cleanly on musl.
LDFLAGS :=

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

# Pull in the generated dependency files (no error on first build).
-include $(OBJS:.o=.d)

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
	rm -f $(TARGET) $(OBJS) $(OBJS:.o=.d)
