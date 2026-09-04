all: ex_original.s
	$(CC) $(CFLAGS) ex_original.s -nostdlib -no-pie -Wl,--build-id=none -Wl,-e,_start -Wl,--section-start=.descriptor_names=0x6f4d00 -Wl,--section-start=.collision_preceding=0x6f7700 -Wl,--section-start=.rodata=0x6f7b00 -Wl,--section-start=.unlabeled_strings=0x6f7d40 -o ex
	@./ex > out.txt

clean:
	rm -f ex out.txt
	rm -fr ex.unstripped ex.s *.old* dl_files *.gtirb

check:
	./ex > /tmp/res.txt
	@diff out.txt /tmp/res.txt && echo TEST OK
