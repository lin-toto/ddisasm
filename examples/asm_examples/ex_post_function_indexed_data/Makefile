all: ex_original.s
	$(CC) $(CFLAGS) ex_original.s -no-pie -o ex
	@./ex

clean:
	rm -f ex
	rm -fr ex.unstripped ex.s *.old* dl_files *.gtirb

check:
	./ex
