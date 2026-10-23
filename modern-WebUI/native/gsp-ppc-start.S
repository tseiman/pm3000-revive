.section .text
.globl _start
.type _start,@function
_start:
    /* The PM3000 glibc 2.3.5 loader supplies argc in r3 and argv in r4. */
    bl main
    li 0,1
    sc
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
