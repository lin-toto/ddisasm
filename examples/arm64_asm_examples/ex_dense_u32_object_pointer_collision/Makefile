CC=aarch64-linux-gnu-gcc
EXEC=qemu-aarch64 -R 0x8000000000 -L /usr/aarch64-linux-gnu

TARGETS=ex out.txt

.PHONY: all clean check
all: out.txt
check: out.txt
ex: src.s
	$(CC) -no-pie \
		-Wl,--section-start=.collision_target=0x820000 \
		-Wl,--section-start=.collision_table=0x8a7000 \
		$^ -o $@
out.txt: ex
	$(EXEC) $^ > $@
clean:
	rm -f $(TARGETS) *.gtirb
