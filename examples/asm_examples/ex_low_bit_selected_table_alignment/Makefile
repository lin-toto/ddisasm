all: ex_original.s
	gcc -nostdlib -no-pie -Wl,-e,_start ex_original.s -o ex
	@./ex > out.txt

clean:
	rm -f ex out.txt
	rm -fr ex.unstripped ex.s *.old* dl_files *.gtirb

check:
	./ex > /tmp/ex_low_bit_selected_table_alignment.res.txt
	@diff out.txt /tmp/ex_low_bit_selected_table_alignment.res.txt && echo TEST OK
