    .text
    .globl _start
    .type _start, @function
_start:
    leaq generator_2_descriptor(%rip), %rsi
    leaq anonymous_string_descriptor(%rip), %rdx
    xorl %edi, %edi
    movl $60, %eax
    syscall
    .size _start, .-_start

    .globl inspect_descriptor_bytes
    .type inspect_descriptor_bytes, @function
inspect_descriptor_bytes:
    movzbl generator_2_descriptor+1(%rip), %eax
    movzbl generator_2_descriptor+2(%rip), %edx
    ret
    .size inspect_descriptor_bytes, .-inspect_descriptor_bytes

    # Function-pointer partners for an interleaved name/parser descriptor
    # array.  The name fields deliberately target anonymous strings whose low
    # bytes look like short NUL-terminated text when stored little-endian.
    .globl parser_0
    .type parser_0, @function
parser_0:
    ret
    .size parser_0, .-parser_0
    .globl parser_1
    .type parser_1, @function
parser_1:
    ret
    .size parser_1, .-parser_1
    .globl parser_2
    .type parser_2, @function
parser_2:
    ret
    .size parser_2, .-parser_2
    .globl parser_3
    .type parser_3, @function
parser_3:
    ret
    .size parser_3, .-parser_3

    .section .descriptor_names,"a",@progbits
    .zero 0x35
.Lparser_name_0:
    .asciz "alpha"
    .zero 0x42 - 0x35 - 6
.Lparser_name_1:
    .asciz "bravo"
    .zero 0x55 - 0x42 - 6
.Lparser_name_2:
    .asciz "charlie"
    .zero 0x68 - 0x55 - 8
.Lparser_name_3:
    .asciz "delta"
    .p2align 3
    .globl parser_descriptor_table
    .type parser_descriptor_table, @object
parser_descriptor_table:
    .quad .Lparser_name_0, parser_0
    .quad .Lparser_name_1, parser_1
    .quad .Lparser_name_2, parser_2
    .quad .Lparser_name_3, parser_3
    .size parser_descriptor_table, .-parser_descriptor_table

    # Match a common run of immutable descriptor objects.  The second and
    # third stored pointers have low bytes that also spell short strings.
    .section .collision_preceding,"a",@progbits
    .type preceding_value, @object
preceding_value:
    .zero 1024
    .size preceding_value, .-preceding_value

    .section .rodata,"a",@progbits
    .globl preceding_descriptor
    .type preceding_descriptor, @object
preceding_descriptor:
    .quad preceding_value
    .long 128
    .long 128
    .long 0
    .long 2
    .size preceding_descriptor, .-preceding_descriptor

    .type generator_19_value, @object
generator_19_value:
    .quad 19
    .size generator_19_value, .-generator_19_value
    .globl generator_19_descriptor
    .type generator_19_descriptor, @object
generator_19_descriptor:
    .quad generator_19_value
    .long 1
    .long 1
    .long 0
    .long 2
    .size generator_19_descriptor, .-generator_19_descriptor

    .type generator_5_value, @object
generator_5_value:
    .quad 5
    .size generator_5_value, .-generator_5_value
    .globl generator_5_descriptor
    .type generator_5_descriptor, @object
generator_5_descriptor:
    .quad generator_5_value
    .long 1
    .long 1
    .long 0
    .long 2
    .size generator_5_descriptor, .-generator_5_descriptor

    .type generator_2_value, @object
generator_2_value:
    .quad 2
    .size generator_2_value, .-generator_2_value
    .globl generator_2_descriptor
    .type generator_2_descriptor, @object
generator_2_descriptor:
    .quad generator_2_value
    .long 1
    .long 1
    .long 0
    .long 2
    .size generator_2_descriptor, .-generator_2_descriptor

    .type following_zero_object, @object
following_zero_object:
    .zero 8
    .quad 1
    .zero 304
    .size following_zero_object, .-following_zero_object

name_0: .asciz "8192"
name_1: .asciz "6144"
name_2: .asciz "4096"
name_3: .asciz "3072"
name_4: .asciz "2048"
name_5: .asciz "1536"
name_6: .asciz "1024"
    # Anonymous short text whose little-endian bytes equal the exact address
    # of generator_2_value (0x6f7b58).  Destination identity alone must not
    # turn these real string bytes into a stored pointer.
    .byte 0x58, 0x7b, 0x6f, 0
    .zero 4

    # The target text begins one byte into this section, so no original symbol
    # exists at 0x6f7d41.  That address has the printable little-endian prefix
    # "A}o\0", which is also a plausible short string when stored as a pointer.
    .section .unlabeled_strings,"a",@progbits
    .byte 0
    .asciz "anonymous target"

    .data
    .globl known_descriptor_table
    .type known_descriptor_table, @object
known_descriptor_table:
    .quad name_0, generator_19_descriptor, preceding_descriptor
    .quad name_1, generator_5_descriptor, preceding_descriptor
    .quad name_2, generator_5_descriptor, preceding_descriptor
    .quad name_3, generator_5_descriptor, preceding_descriptor
    .quad name_4, generator_2_descriptor, preceding_descriptor
    .quad name_5, generator_2_descriptor, preceding_descriptor
    .quad name_6, generator_2_descriptor, preceding_descriptor
    .zero 24
    .size known_descriptor_table, .-known_descriptor_table

    .p2align 3
    .globl anonymous_string_descriptor
    .type anonymous_string_descriptor, @object
anonymous_string_descriptor:
    .quad 0x6f7d41
    .quad 1
    .quad 0
    .quad 0
    .quad 0
    .size anonymous_string_descriptor, .-anonymous_string_descriptor
