CC := gcc

CFLAGS := -O2 -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security
CFLAGS += -Wshadow -Wconversion -Wno-sign-conversion
CFLAGS += -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2 -ldl

LDFLAGS :=

TARGET := arm64_edr_hooks_check

SRCS := arm64_edr_hooks_check.c

OBJS := $(SRCS:.c=.o)

# Default target
.PHONY: all static clean run

all: $(TARGET)

# Main binary
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

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
	rm -f $(TARGET)

