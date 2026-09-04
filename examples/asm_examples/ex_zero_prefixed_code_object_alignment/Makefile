all: ex_original.s
	gcc -no-pie ex_original.s -o ex
	@./ex > out.txt

clean:
	rm -f ex out.txt
	rm -fr ex.unstripped ex.s *.old* dl_files *.gtirb

check:
	./ex > /tmp/ex_zero_prefixed_code_object_alignment.res.txt
	@diff out.txt /tmp/ex_zero_prefixed_code_object_alignment.res.txt && echo TEST OK
