CC = riscv64-linux-gnu-gcc
EXEC = qemu-riscv64 -R 0x4000000000 -L /usr/riscv64-linux-gnu

TARGETS = ex out.txt

.PHONY: all clean check
all: out.txt
check: out.txt

ex: src.s
	$(CC) $(CFLAGS) -no-pie -Wa,-mno-relax -Wl,--no-relax \
		-Wl,--section-start=.collision_text=0x70040 \
		-Wl,--section-start=.collision_data=0x71000 \
		-Wl,--section-start=.collision_jump_table=0x72000 \
		-Wl,--section-start=.collision_string_target=0x354000 $^ -o $@

out.txt: ex
	$(EXEC) $^ > $@

clean:
	rm -f $(TARGETS) *.gtirb
