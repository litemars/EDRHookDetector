CC := gcc
CFLAGS := -O2 -ldl

TARGETS :=  arm64_edr_hooks_check

.PHONY: all clean run scan-pid

all: $(TARGETS)

arm64_edr_hooks_check: arm64_edr_hooks_check.c
	$(CC) $(CFLAGS) -o $@ $<

run: 
	./$(TARGETS)

clean:
	rm -f $(TARGETS)
