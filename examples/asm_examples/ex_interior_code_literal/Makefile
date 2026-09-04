all: ex_original.s
	$(CC) $(CFLAGS) ex_original.s -no-pie -Wl,--section-start=.collision_string_exact_target=0x323730 -Wl,--section-start=.collision_format_target=0x434240 -Wl,--section-start=.collision_zero_prefix_target=0x484400 -Wl,--section-start=.collision_exact_code=0x500000 -Wl,--section-start=.collision_relative_table=0x510000 -Wl,--section-start=.collision_relative_targets=0x510040 -Wl,--section-start=.collision_relative_target2=0x520000 -Wl,--section-start=.collision=0x6c6100 -Wl,--section-start=.collision_pem_exact_target=0x6d6570 -Wl,--section-start=.collision_data=0x700000 -Wl,--section-start=.collision_short_string_target=0x737360 -Wl,--section-start=.collision_repeated_string_target=0x742b50 -Wl,--section-start=.collision_single_char_exact_target=0x770000 -o ex
	$(CC) $(CFLAGS) ex_original.s -pie -Wl,--section-start=.collision_string_exact_target=0x323730 -Wl,--section-start=.collision_format_target=0x434240 -Wl,--section-start=.collision_zero_prefix_target=0x484400 -Wl,--section-start=.collision_exact_code=0x500000 -Wl,--section-start=.collision_relative_table=0x510000 -Wl,--section-start=.collision_relative_targets=0x510040 -Wl,--section-start=.collision_relative_target2=0x520000 -Wl,--section-start=.collision=0x6c6100 -Wl,--section-start=.collision_pem_exact_target=0x6d6570 -Wl,--section-start=.collision_data=0x700000 -Wl,--section-start=.collision_short_string_target=0x737360 -Wl,--section-start=.collision_repeated_string_target=0x742b50 -Wl,--section-start=.collision_single_char_exact_target=0x770000 -o ex_reloc
	@./ex > out.txt
clean:
	rm -f ex ex_reloc out.txt
	rm -fr ex.unstripped ex.s *.old* dl_files *.gtirb
check:
	./ex > /tmp/res.txt
	@diff out.txt /tmp/res.txt && echo TEST OK
