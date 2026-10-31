.section .text
.globl _start
.type _start,@function
_start:
    /* Firmware ld-2.3.5.so transfers argc/argv in r3/r4. */
    bl main
    li 0,1
    sc
    b .
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
